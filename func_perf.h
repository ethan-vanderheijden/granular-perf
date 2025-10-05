#ifndef FUNC_PERF_H
#define FUNC_PERF_H

// includes latency measurement
#define MAX_EVENTS 16

typedef struct {
    int hist_start;
    int bucket_size;
    int num_buckets;
    int avg;
    int constrain_avg;
} hist_params_t;

typedef struct {
    unsigned long long sum;
    unsigned long long count;
} running_avg_t;

#endif
