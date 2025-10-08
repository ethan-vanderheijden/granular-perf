#include "func_perf.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <dirent.h>
#include <libgen.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "func_perf.bpf.skel.h"

#define MAX_THREADS 64

static bool verbose;
static volatile int exited = 0;

const char help_fmt[] =
    "A tool to measure perf events or latency for a specific function using uprobe + eBPF.\n"
    "\n"
    "Usage: %1$s [-v] [-t <tid1>,...] -e <event1>,<event2>,... <pid> <binary_path> <pattern>\n"
    "  -v: verbose output\n"
    "  -t: aggregate event counters for these comma-separated threads ids, or all threads if 'all' "
    "is supplied\n"
    "  -e: comma-separated list of events to measure\n"
    "\n"
    "Event format: <type>:<config>:<start-stop-step>[:avg|constrained_avg]\n"
    "  where `type` and `config` correspond to the argument attributes of perf_event_open(2),\n"
    "  latency is a special event that measures function latency,\n"
    "  `start-stop-step` define the histogram range and bucket size, and\n"
    "  `avg` records the average of all event values (can be constrained to values in histogram "
    "range)\n"
    "\n"
    "Example:\n"
    "  %1$s -v -t all -e "
    "latency:500-1500-100:constrained_avg,hardware:cpu-cycles:10000-200000-10000 "
    "12345 /bin/bash '*readline*'\n";

typedef struct {
    char *name;
    uint32_t type;
    uint64_t config;
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

void lowercase(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower(str[i]);
    }
}

uint32_t parse_perf_type(char *type_str) {
    lowercase(type_str);
    if (strcmp(type_str, "hardware") == 0 || strcmp(type_str, "hw") == 0) {
        return PERF_TYPE_HARDWARE;
    } /*else if (strcmp(type_str, "raw") == 0) {
        return PERF_TYPE_RAW;
    }*/
    else {
        fprintf(stderr, "Unsupported event type: %s\n", type_str);
        return -1;
    }
}

uint64_t parse_perf_hw_config(char *config_str) {
    lowercase(config_str);
    if (strcmp(config_str, "cpu-cycles") == 0) {
        return PERF_COUNT_HW_CPU_CYCLES;
    } else if (strcmp(config_str, "instructions") == 0) {
        return PERF_COUNT_HW_INSTRUCTIONS;
    } else if (strcmp(config_str, "cache-references") == 0) {
        return PERF_COUNT_HW_CACHE_REFERENCES;
    } else if (strcmp(config_str, "cache-misses") == 0) {
        return PERF_COUNT_HW_CACHE_MISSES;
    } else if (strcmp(config_str, "branch-instructions") == 0) {
        return PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    } else if (strcmp(config_str, "branch-misses") == 0) {
        return PERF_COUNT_HW_BRANCH_MISSES;
    } else if (strcmp(config_str, "bus-cycles") == 0) {
        return PERF_COUNT_HW_BUS_CYCLES;
    } else if (strcmp(config_str, "stalled-cycles-frontend") == 0) {
        return PERF_COUNT_HW_STALLED_CYCLES_FRONTEND;
    } else if (strcmp(config_str, "stalled-cycles-backend") == 0) {
        return PERF_COUNT_HW_STALLED_CYCLES_BACKEND;
    } else if (strcmp(config_str, "ref-cpu-cycles") == 0) {
        return PERF_COUNT_HW_REF_CPU_CYCLES;
    } else {
        fprintf(stderr, "Unsupported hardware config: %s\n", config_str);
        return -1;
    }
}

event_t *parse_single_event(char *event_str) {
    event_t *event = calloc(1, sizeof(event_t));
    if (event == NULL) {
        fprintf(stderr, "Failed to allocate memory for event\n");
        return NULL;
    }

    char *saved;
    char *token = strtok_r(event_str, ":", &saved);
    // 0 = parsing type, 1 = parsing config, 2 = parsing hist params, 3 = parsing avg, 4 = done
    int state = 0;
    while (token != NULL) {
        switch (state) {
            case 0:
                if (strcmp(token, "latency") == 0) {
                    event->latency_event = true;
                    event->name = "latency";
                    state = 2;
                } else {
                    event->type = parse_perf_type(token);
                    if (event->type == (uint32_t)-1) {
                        goto err;
                    }
                    state = 1;
                }
                break;
            case 1:
                if (event->type == PERF_TYPE_HARDWARE) {
                    event->config = parse_perf_hw_config(token);
                    if (event->config == (uint64_t)-1) {
                        goto err;
                    }
                    event->name = token;
                    state = 2;
                }
                break;
            case 2: {
                int hist_end;
                if (sscanf(token, "%d-%d-%d", &event->hist_start, &hist_end, &event->bucket_size) !=
                    3) {
                    fprintf(stderr, "Failed to parse histogram params: %s\n", token);
                    goto err;
                }
                event->num_buckets = 2 + (hist_end - event->hist_start + event->bucket_size - 1) /
                                             event->bucket_size;
                state = 3;
                break;
            }
            case 3:
                lowercase(token);
                if (strcmp(token, "avg") == 0) {
                    event->avg = true;
                    state = 4;
                } else if (strcmp(token, "constrained_avg") == 0) {
                    event->avg = true;
                    event->constrain_avg = true;
                    state = 4;
                } else {
                    fprintf(stderr, "Unsupported avg option: %s\n", token);
                    goto err;
                }
                break;
            default:
                fprintf(stderr, "Unexpected token: %s\n", token);
                goto err;
        }

        token = strtok_r(NULL, ":", &saved);
    }

    if (state < 3) {
        fprintf(stderr, "Incomplete event specification.\n");
        goto err;
    }

    return event;

err:
    free(event);
    return NULL;
}

event_t **parse_events(char *event_str, int *num_events) {
    event_t **events = calloc(MAX_EVENTS, sizeof(event_t *));
    if (events == NULL) {
        fprintf(stderr, "Failed to allocate memory for events array\n");
        return NULL;
    }

    char *saved;
    char *token = strtok_r(event_str, ",", &saved);
    int index = 0;
    while (token != NULL) {
        if (index >= MAX_EVENTS) {
            fprintf(stderr, "We only support up to %d events\n", MAX_EVENTS);
            goto err;
        }

        event_t *event = parse_single_event(token);
        if (event == NULL) {
            fprintf(stderr, "Failed to parse event %d\n", index + 1);
            goto err;
        }
        events[index++] = event;

        token = strtok_r(NULL, ",", &saved);
    }
    *num_events = index;

    return events;

err:
    for (int i = 0; i < index; i++) {
        free(events[i]);
    }
    free(events);
    return NULL;
}

int open_perf_event(uint32_t type, uint64_t config, int pid, int group_fd) {
    struct perf_event_attr attr = {
        .type = type,
        .config = config,
        .inherit = 0,
        .pinned = 1,
        .size = sizeof(attr),
    };
    int fd = syscall(SYS_perf_event_open, &attr, pid, -1, group_fd, 0);
    if (fd == -1) {
        fprintf(stderr, "Failed to open perf event (type=%u, config=0x%lx) for pid %d: %s\n", type,
                config, pid, strerror(errno));
    }
    return fd;
}

uint64_t sum_buckets(struct func_perf_bpf **skels, int num_skels, int index) {
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
    return count;
}

void print_histogram(struct func_perf_bpf **skels, int num_skels, event_t *event, int hist_offset) {
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

void print_avg(struct func_perf_bpf **skels, int num_skels, int avg_index) {
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
int attach_to_thread(int tgid, int pid, struct func_perf_bpf **skel_ptr, char *path, char *pattern,
                     event_t **events, int num_events) {
    LIBBPF_OPTS(bpf_uprobe_multi_opts, uprobe_multi_opts);

    struct func_perf_bpf *skel = func_perf_bpf__open();
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

    bpf_map__set_max_entries(skel->maps.hist_params, num_events);
    bpf_map__set_max_entries(skel->maps.perf_events, num_perf_events);
    bpf_map__set_max_entries(skel->maps.counter_starts, num_perf_events);
    bpf_map__set_max_entries(skel->maps.multi_hist, total_buckets);
    bpf_map__set_max_entries(skel->maps.avgs, events_with_avg);

    if (func_perf_bpf__load(skel) != 0) {
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
            int fd = open_perf_event(event->type, event->config, pid, group_fd);
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
    func_perf_bpf__destroy(skel);
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
    char *tidArg = NULL;
    event_t **events;
    int num_events;
    int opt;
    while ((opt = getopt(argc, argv, "vht:e:")) != -1) {
        switch (opt) {
            case 't':
                tidArg = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'e':
                events = parse_events(optarg, &num_events);
                if (events != NULL) {
                    break;
                }
            default:
                fprintf(stderr, help_fmt, basename(argv[0]));
                return opt != 'h';
        }
    }

    pid_t pid;
    char *path;
    char *pattern;
    if (optind + 3 != argc) {
        fprintf(stderr, help_fmt, basename(argv[0]));
        return 1;
    } else {
        pid = atoi(argv[optind]);
        path = argv[optind + 1];
        pattern = argv[optind + 2];
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

    struct func_perf_bpf **skels = calloc(num_threads, sizeof(struct func_perf_bpf *));
    for (int i = 0; i < num_threads; i++) {
        skels[i] = malloc(sizeof(struct func_perf_bpf));
        memset(skels[i], 0, sizeof(struct func_perf_bpf));
        if (attach_to_thread(pid, tids[i], &skels[i], path, pattern, events, num_events) != 0) {
            for (int j = 0; j < i; j++) {
                func_perf_bpf__destroy(skels[j]);
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

    printf("\n\n");

    int hist_offset = 0;
    int avg_index = 0;
    for (int i = 0; i < num_events; i++) {
        event_t *event = events[i];

        printf("Event: %s\n", event->name);
        printf("=========================================\n");
        print_histogram(skels, num_threads, event, hist_offset);
        hist_offset += event->num_buckets;

        if (event->avg) {
            print_avg(skels, num_threads, avg_index);
            avg_index++;
        }
    }

    for (int i = 0; i < num_threads; i++) {
        func_perf_bpf__destroy(skels[i]);
    }

    return 0;
}
