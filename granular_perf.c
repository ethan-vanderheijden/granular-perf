#include "granular_perf.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <dirent.h>
#include <libgen.h>
#include <linux/perf_event.h>
#include <perfmon/pfmlib.h>
#include <perfmon/pfmlib_perf_event.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "granular_perf.bpf.skel.h"

#define MAX_THREADS 64

static bool verbose;
static volatile int exited = 0;

const char help_fmt[] =
    "A tool to measure perf events or latency for a specific function using uprobe + eBPF.\n"
    "\n"
    "Usage: %1$s [-v] [-t <tid1>,...] -e <event1> -e <event2> -e ... <pid> <pattern>\n"
    "  -v: verbose output\n"
    "  -t: aggregate event counters for these comma-separated threads ids, or all threads if 'all' "
    "is supplied\n"
    "  -b: path to binary (detected based on PID if not supplied)\n"
    "  -e: event to measure\n"
    "\n"
    "Event format: <event_string>,<start-stop-step>[,avg|constrained_avg]\n"
    "  where `event_string` is an event as parsed by libpfm,\n"
    "  latency is a special event that measures function latency,\n"
    "  `start-stop-step` define the histogram range and bucket size, and\n"
    "  `avg` records the average of all event values (can be constrained to values in histogram "
    "range)\n"
    "\n"
    "Example:\n"
    "  %1$s -v -t all -e "
    "latency,500-1500-100,constrained_avg -e perf::cpu-cycles,10000-200000-10000 "
    "-b /bin/bash 12345 '*readline*'\n";

typedef struct {
    char *name;
    struct perf_event_attr perf_event;
    bool latency_event;
    int hist_start;
    int bucket_size;
    int num_buckets;
    bool avg;
    bool constrain_avg;
} event_t;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && !verbose) return 0;
    return vfprintf(stderr, format, args);
}

event_t *parse_single_event(char *event_str) {
    event_t *event = calloc(1, sizeof(event_t));
    if (event == NULL) {
        fprintf(stderr, "Failed to allocate memory for event\n");
        return NULL;
    }

    char *token = strtok(event_str, ",");
    // 0 = parsing event string, 1 = parsing hist params, 2 = parsing avg, 3 = done
    int state = 0;
    while (token != NULL) {
        switch (state) {
            case 0:
                if (strcasecmp(token, "latency") == 0) {
                    event->latency_event = true;
                    event->name = "latency";
                } else {
                    event->latency_event = false;
                    event->name = token;

                    pfm_perf_encode_arg_t args;
                    memset(&args, 0, sizeof(args));
                    args.attr = &event->perf_event;
                    args.size = sizeof(args);
                    pfm_err_t ret = pfm_get_os_event_encoding(token, PFM_PLM0 | PFM_PLM3, PFM_OS_PERF_EVENT, &args);
                    if (ret != PFM_SUCCESS) {
                        fprintf(stderr, "Failed to parse event string '%s': %s\n", token,
                                pfm_strerror(ret));
                        goto err;
                    }
                }
                state = 1;
                break;
            case 1: {
                int hist_end;
                if (sscanf(token, "%d-%d-%d", &event->hist_start, &hist_end, &event->bucket_size) !=
                    3) {
                    fprintf(stderr, "Failed to parse histogram params: %s\n", token);
                    goto err;
                }
                event->num_buckets = 2 + (hist_end - event->hist_start + event->bucket_size - 1) /
                                             event->bucket_size;
                state = 2;
                break;
            }
            case 2:
                if (strcasecmp(token, "avg") == 0) {
                    event->avg = true;
                    state = 3;
                } else if (strcasecmp(token, "constrained_avg") == 0) {
                    event->avg = true;
                    event->constrain_avg = true;
                    state = 3;
                } else {
                    fprintf(stderr, "Unsupported avg option: %s\n", token);
                    goto err;
                }
                break;
            default:
                fprintf(stderr, "Unexpected token: %s\n", token);
                goto err;
        }

        token = strtok(NULL, ",");
    }

    if (state < 2) {
        fprintf(stderr, "Incomplete event specification.\n");
        goto err;
    }

    return event;

err:
    free(event);
    return NULL;
}

int open_perf_event(struct perf_event_attr template, int pid, int group_fd) {
    struct perf_event_attr attr;
    memcpy(&attr, &template, sizeof(attr));
    attr.inherit = 0;
    attr.size = sizeof(attr);
    attr.sample_freq = 0;
    attr.sample_period = 0;
    attr.sample_type = 0;
    attr.read_format = 0;
    int fd = syscall(SYS_perf_event_open, &attr, pid, -1, group_fd, 0);
    if (fd == -1) {
        fprintf(stderr, "Failed to open perf event (type=%u, config=0x%llx) for pid %d: %s\n",
                attr.type, attr.config, pid, strerror(errno));
    }
    return fd;
}

uint64_t sum_buckets(struct granular_perf_bpf **skels, int num_skels, int index) {
    uint64_t total = 0;
    for (int i = 0; i < num_skels; i++) {
        uint64_t count = 0;
        if (bpf_map_lookup_elem(bpf_map__fd(skels[i]->maps.multi_hist), &index, &count) == 0) {
            total += count;
        } else {
            fprintf(stderr, "Failed to lookup histogram bucket %d in skeleton %d\n", index, i);
        }
    }
    return total;
}

int letters_in_num(int num) {
    int count = 0;
    while (num > 0) {
        num /= 10;
        count++;
    }
    if (count < 3) {
        count = 3;
    }
    return count;
}

void print_histogram(struct granular_perf_bpf **skels, int num_skels, event_t *event, int hist_offset) {
    uint64_t max_value = 0;
    for (int i = 0; i < event->num_buckets; i++) {
        uint32_t bucket = hist_offset + i;
        uint64_t count = sum_buckets(skels, num_skels, bucket);
        if (count > max_value) {
            max_value = count;
        }
    }

    int value_width = letters_in_num(max_value);
    int hist_end = event->hist_start + event->bucket_size * (event->num_buckets - 2);
    int bucket_width = letters_in_num(hist_end);

    const int HIST_SCALE = 40;
    for (int i = 0; i < event->num_buckets; i++) {
        uint32_t bucket = hist_offset + i;
        uint64_t count = sum_buckets(skels, num_skels, bucket);

        if (i == 0) {
            printf("(%*s, %*d) | ", bucket_width, "...", bucket_width, event->hist_start);
        } else if (i == event->num_buckets - 1) {
            printf("[%*d, %*s) | ", bucket_width, hist_end, bucket_width, "...");
        } else {
            printf("[%*d, %*d) | ", bucket_width, event->hist_start + (i - 1) * event->bucket_size,
                   bucket_width, event->hist_start + i * event->bucket_size);
        }
        printf("%*lu : ", value_width, count);
        if (max_value != 0) {
            for (int j = 0; j < (HIST_SCALE * count) / max_value; j++) {
                printf("*");
            }
        }
        printf("\n");
    }
}

void print_avg(struct granular_perf_bpf **skels, int num_skels, int avg_index) {
    running_avg_t avg = {
        .sum = 0,
        .count = 0,
    };
    for (int i = 0; i < num_skels; i++) {
        running_avg_t tmp;
        if (bpf_map_lookup_elem(bpf_map__fd(skels[i]->maps.avgs), &avg_index, &tmp) != 0) {
            fprintf(stderr, "Failed to lookup avg %d in skeleton %d\n", avg_index, i);
            return;
        }
        avg.sum += tmp.sum;
        avg.count += tmp.count;
    }
    if (avg.count == 0) {
        printf("Avg: N/A (no samples)\n");
    } else {
        printf("Avg: %.3f (count: %llu)\n", ((double)avg.sum) / avg.count, avg.count);
    }
}

static void sigint_handler(int _) { exited = 1; }

// the eBPF program is attached to the parent process (tgid) but will filter function calls
// based on the thread's pid
int attach_to_thread(int tgid, int pid, struct granular_perf_bpf **skel_ptr, char *path, char *pattern,
                     event_t **events, int num_events) {
    LIBBPF_OPTS(bpf_uprobe_multi_opts, uprobe_multi_opts);

    struct granular_perf_bpf *skel = granular_perf_bpf__open();
    *skel_ptr = skel;
    bpf_program__set_expected_attach_type(skel->progs.func_entry, BPF_TRACE_UPROBE_MULTI);
    bpf_program__set_expected_attach_type(skel->progs.func_exit, BPF_TRACE_UPROBE_MULTI);
    skel->rodata->instrument_latency = false;
    skel->rodata->target_pid = pid;

    int num_perf_events = num_events;
    int total_buckets = 0;
    int events_with_avg = 0;
    for (int i = 0; i < num_events; i++) {
        event_t *event = events[i];
        if (event->latency_event) {
            num_perf_events--;
            skel->rodata->instrument_latency = true;
        }
        total_buckets += event->num_buckets;
        if (event->avg) {
            events_with_avg++;
        }
    }

    skel->rodata->num_perf_events = num_perf_events;
    if (num_perf_events == 0) {
        // maps must have at least 1 entry or it fails to load
        num_perf_events = 1;
    }
    if (events_with_avg == 0) {
        events_with_avg = 1;
    }

    bpf_map__set_max_entries(skel->maps.hist_params, num_events);
    bpf_map__set_max_entries(skel->maps.perf_events, num_perf_events);
    bpf_map__set_max_entries(skel->maps.counter_starts, num_perf_events);
    bpf_map__set_max_entries(skel->maps.multi_hist, total_buckets);
    bpf_map__set_max_entries(skel->maps.avgs, events_with_avg);

    if (granular_perf_bpf__load(skel) != 0) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        return 1;
    }

    int group_fd = -1;
    for (int i = 0; i < num_events; i++) {
        event_t *event = events[i];
        hist_params_t params = {
            .hist_start = event->hist_start,
            .bucket_size = event->bucket_size,
            .num_buckets = event->num_buckets,
            .avg = event->avg,
            .constrain_avg = event->constrain_avg,
        };
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.hist_params), &i, &params, BPF_ANY)) {
            fprintf(stderr, "Failed to set histogram params for event %d\n", i + 1);
            goto err;
        }
        if (!event->latency_event) {
            int fd = open_perf_event(event->perf_event, pid, group_fd);
            if (fd == -1) {
                goto err;
            }
            if (group_fd == -1) {
                group_fd = fd;
            }
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.perf_events), &i, &fd, BPF_ANY)) {
                fprintf(stderr, "Failed to set perf event fd for event %d: %s\n", i + 1,
                        strerror(errno));
                close(fd);
                goto err;
            }
        }
    }

    printf("Attaching to process %d (tgid %d)\n", pid, tgid);

    uprobe_multi_opts.retprobe = false;
    skel->links.func_entry = bpf_program__attach_uprobe_multi(skel->progs.func_entry, tgid, path,
                                                              pattern, &uprobe_multi_opts);
    if (!skel->links.func_entry) {
        perror("Failed to attach entry uprobe");
        goto err;
    }

    uprobe_multi_opts.retprobe = true;
    skel->links.func_exit = bpf_program__attach_uprobe_multi(skel->progs.func_exit, tgid, path,
                                                             pattern, &uprobe_multi_opts);
    if (!skel->links.func_exit) {
        perror("Failed to attach exit uprobe");
        goto err;
    }

    return 0;

err:
    granular_perf_bpf__destroy(skel);
    return 1;
}

int get_threads_in_tgid(int tgid, int **tids, int *num_tids) {
    char task_path[128];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", tgid);
    DIR *dir = opendir(task_path);
    if (dir == NULL) {
        perror("Failed to open task directory");
        return -1;
    }

    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) {
            continue;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        int tid = atoi(entry->d_name);
        if (tid > 0) {
            if (count >= MAX_THREADS) {
                fprintf(stderr, "Too many threads in tgid %d, max supported is %d\n", tgid,
                        MAX_THREADS);
                free(*tids);
                closedir(dir);
                return -1;
            }
            (*tids)[count] = tid;
            count++;
        }
    }
    closedir(dir);
    *num_tids = count;
    return 0;
}

int main(int argc, char **argv) {
    pfm_err_t ret = pfm_initialize();
    if (ret != PFM_SUCCESS) {
        fprintf(stderr, "Failed to initialize libpfm: %s\n", pfm_strerror(ret));
        return 1;
    }

    char *tidArg = NULL;
    event_t **events = calloc(MAX_EVENTS, sizeof(event_t *));
    int num_events = 0;
    bool instrumenting_latency = false;
    char *binary = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "vb:ht:e:")) != -1) {
        switch (opt) {
            case 't':
                tidArg = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'b':
                binary = optarg;
                break;
            case 'e':
                if (num_events >= MAX_EVENTS) {
                    fprintf(stderr, "We only support up to %d events\n", MAX_EVENTS);
                    return 1;
                }
                events[num_events] = parse_single_event(optarg);
                if (events[num_events] == NULL) {
                    return 1;
                }
                if (events[num_events]->latency_event) {
                    if (instrumenting_latency) {
                        fprintf(stderr, "Only one latency event can be specified\n");
                        return 1;
                    } else {
                        instrumenting_latency = true;
                    }
                }
                num_events++;
                if (events != NULL) {
                    break;
                }
            default:
                fprintf(stderr, help_fmt, basename(argv[0]));
                return opt != 'h';
        }
    }

    // BPF program expects latency event to be the last event
    for(int i = 0; i < num_events - 1; i++) {
        event_t *event = events[i];
        if (event->latency_event) {
            events[i] = events[num_events - 1];
            events[num_events - 1] = event;
            break;
        }
    }

    pid_t pid;
    char *pattern;
    if (optind + 2 != argc) {
        fprintf(stderr, help_fmt, basename(argv[0]));
        return 1;
    } else {
        pid = atoi(argv[optind]);
        pattern = argv[optind + 1];
    }

    if (binary == NULL) {
        char proc_path[128];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
        binary = realpath(proc_path, NULL);
        if (binary == NULL) {
            fprintf(stderr, "Failed to resolve binary path for pid %d: %s\n", pid, strerror(errno));
            return -1;
        }
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    libbpf_set_print(libbpf_print_fn);

    int num_threads;
    int *tids;
    if (tidArg != NULL) {
        tids = malloc(MAX_THREADS * sizeof(int));
        if (tids == NULL) {
            fprintf(stderr, "Failed to allocate memory for tids\n");
            return -1;
        }

        if (strcmp(tidArg, "all") == 0) {
            if (get_threads_in_tgid(pid, &tids, &num_threads) != 0) {
                return 1;
            }
        } else {
            char *token = strtok(tidArg, ",");
            tids[0] = pid;
            int index = 1;
            while (token != NULL) {
                int tid = atoi(token);
                if (tid > 0) {
                    if (index >= MAX_THREADS) {
                        fprintf(stderr, "Too many threads specified, max supported is %d\n",
                                MAX_THREADS);
                        return -1;
                    }

                    tids[index] = tid;
                    index++;
                    token = strtok(NULL, ",");
                }
            }
            num_threads = index;
        }
    } else {
        num_threads = 1;
        tids = malloc(sizeof(int));
        tids[0] = pid;
    }

    struct granular_perf_bpf **skels = calloc(num_threads, sizeof(struct granular_perf_bpf *));
    for (int i = 0; i < num_threads; i++) {
        skels[i] = malloc(sizeof(struct granular_perf_bpf));
        memset(skels[i], 0, sizeof(struct granular_perf_bpf));
        if (attach_to_thread(pid, tids[i], &skels[i], binary, pattern, events, num_events) != 0) {
            for (int j = 0; j < i; j++) {
                granular_perf_bpf__destroy(skels[j]);
            }
            return 1;
        }
    }

    printf("Now tracing... Ctrl-C to end.\n");

    while (!exited) {
        pause();
    }

    for (int i = 0; i < num_threads; i++) {
        bpf_link__destroy(skels[i]->links.func_entry);
        bpf_link__destroy(skels[i]->links.func_exit);
        skels[i]->links.func_entry = NULL;
        skels[i]->links.func_exit = NULL;
    }

    printf("\n");

    int hist_offset = 0;
    int avg_index = 0;
    for (int i = 0; i < num_events; i++) {
        event_t *event = events[i];

        printf("\nEvent: %s\n", event->name);
        printf("=========================================\n");
        print_histogram(skels, num_threads, event, hist_offset);
        hist_offset += event->num_buckets;

        if (event->avg) {
            print_avg(skels, num_threads, avg_index);
            avg_index++;
        }
    }

    for (int i = 0; i < num_threads; i++) {
        granular_perf_bpf__destroy(skels[i]);
    }

    return 0;
}
