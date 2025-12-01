#include "vmlinux.h"

#include "granular_perf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// total number of perf events we are instrumenting (not including latency "event")
const volatile int num_perf_events;
// whether we should record function latency
const volatile bool instrument_latency;
const volatile int target_pid;

unsigned long int start_timestamp;

#define LOOP_EVENTS(var) for (int var = 0; var < MAX_EVENTS - 1 && var < num_perf_events; var++)

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, hist_params_t);
    // max_entries is set in userspace by libbpf, equal to num_perf_events + 1 (if
    // `instrument_latency`)
} hist_params SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, u32);
    __type(value, u32);
    // max_entries is set in userspace by libbpf, equal to num_perf_events
} perf_events SEC(".maps");

// record start event counter when function entry is hit
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct bpf_perf_event_value);
    // max_entries is set in userspace by libbpf, equal to num_perf_events
} counter_starts SEC(".maps");

// all histograms are multiplexed into a single array
// if `instrument_latency` is true, last `num_buckets` entries corresponds to latency histogram
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    // max_entries is set in userspace by libbpf
} multi_hist SEC(".maps");

// running averages for each histogram that we are measuring average for (<= num_perf_events + 1)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, running_avg_t);
    // max_entries is set in userspace by libbpf (<= num_perf_events + 1)
} avgs SEC(".maps");

SEC("uprobe")
int BPF_UPROBE(func_entry) {
    if ((bpf_get_current_pid_tgid() & 0xFFFFFFFF) != target_pid) {
        return 0;
    }

    LOOP_EVENTS(event) {
        struct bpf_perf_event_value start_val;
        u32 key = event;
        long err = bpf_perf_event_read_value(&perf_events, key, &start_val, sizeof(start_val));
        if (!err) {
            bpf_map_update_elem(&counter_starts, &key, &start_val, BPF_ANY);
        } else {
            bpf_printk("Error reading perf event %d: %ld", event, err);
        }
    }

    if (instrument_latency) {
        start_timestamp = bpf_ktime_get_ns();
    }

    return 0;
}

void process_datapoint(hist_params_t *params, u64 value, u32 hist_offset, u32 hist_avg_index) {
    u32 bucket = 0;
    if (value >= params->hist_start) {
        bucket = 1 + (value - params->hist_start) / params->bucket_size;
        if (bucket >= params->num_buckets) {
            bucket = params->num_buckets - 1;
        }
    }
    bucket += hist_offset;

    u64 *count = bpf_map_lookup_elem(&multi_hist, &bucket);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    if (params->avg) {
        running_avg_t *avg = bpf_map_lookup_elem(&avgs, &hist_avg_index);
        if (avg) {
            if (!params->constrain_avg ||
                (value >= params->hist_start &&
                 value <= (params->hist_start + params->bucket_size * (params->num_buckets - 2)))) {
                __sync_fetch_and_add(&avg->sum, value);
                __sync_fetch_and_add(&avg->count, 1);
            }
        }
    }
}

SEC("uretprobe")
int BPF_URETPROBE(func_exit) {
    if ((bpf_get_current_pid_tgid() & 0xFFFFFFFF) != target_pid) {
        return 0;
    }

    u64 end_timestamp;
    if (instrument_latency) {
        end_timestamp = bpf_ktime_get_ns();
    }

    u32 hist_offset = 0;
    u32 hist_avg_index = 0;
    LOOP_EVENTS(event) {
        u32 key = event;
        struct bpf_perf_event_value end_val;

        hist_params_t *params = bpf_map_lookup_elem(&hist_params, &key);
        if (params) {
            long err = bpf_perf_event_read_value(&perf_events, key, &end_val, sizeof(end_val));
            if (!err) {
                struct bpf_perf_event_value *start_val = bpf_map_lookup_elem(&counter_starts, &key);
                if (start_val) {
                    u64 t_enabled = end_val.enabled - start_val->enabled;
                    u64 t_running = end_val.running - start_val->running;
                    if (t_enabled != 0 && t_running != 0) {
                        u64 delta = (end_val.counter - start_val->counter) * t_enabled / t_running;
                        process_datapoint(params, delta, hist_offset, hist_avg_index);
                    }
                    bpf_map_delete_elem(&counter_starts, &key);
                }
            }

            hist_offset += params->num_buckets;
            if (params->avg) {
                hist_avg_index++;
            }
        }
    }

    if (instrument_latency) {
        u32 divisor = 1000;  // for now, hardcode measurements in microseconds

        u64 delta = (end_timestamp - start_timestamp) / divisor;
        u32 key = num_perf_events;
        hist_params_t *params = bpf_map_lookup_elem(&hist_params, &key);
        if (params) {
            process_datapoint(params, delta, hist_offset, hist_avg_index);
        }
    }

    return 0;
}
