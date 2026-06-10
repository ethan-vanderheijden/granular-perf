#!/usr/bin/env python3

import matplotlib.pyplot as plt
import re
import fileinput

fig_index = 1


def draw_histogram(buckets, data, title, subtitles=[]):
    global fig_index
    fig = plt.figure(fig_index)
    fig_index += 1

    if len(buckets) == 2:
        plot = plt.bar(
            buckets, [d / sum(data) for d in data], align="edge", width=1, edgecolor="black"
        )
        plot = plt.gca()
    else:
        plot = plt.bar(
            buckets, [d / sum(data) for d in data], align="edge", width=1, edgecolor="black"
        )
        plot = plt.gca()
        plot.set_xticklabels(plot.get_xticklabels(), rotation=45, horizontalalignment="center")

    plot.set_ylabel("Probability")
    plot.set_xlabel("Count")
    pad = 10
    if subtitles:
        pad += 15 * len(subtitles)
    plt.suptitle(title, fontsize=15)

    if subtitles:
        subtitle = ""
        for s in subtitles:
            subtitle += "\n" + s

        plot.set_title(subtitle, pad=8, fontsize=12, color=(0.6, 0.6, 0.6))

    fig.show()


if __name__ == "__main__":
    buckets = []
    data = []
    title = None
    avg_line = None
    stddev_line = None
    # 0 = reading title, 1 = reading first bar, 2 = reading bars, 3 = reading avg, 4 = reading std dev
    # bars are in the format "[25500, 25600) | 15253 : *********************"
    state = 0
    for line in fileinput.input():
        line = line.strip()

        if state == 3:
            avg_line = line
            state = 4
        elif state == 4:
            stddev_line = line
            state = 0
            draw_histogram(buckets, data, title, [avg_line, stddev_line])
            buckets = []
            data = []
            title = None
            avg_line = None
            stddev_line = None
            continue

        if not line:
            continue

        if line.strip("=") == "":
            state = 1
        elif state == 0:
            title = line
        elif state == 1:
            numbers = re.findall(r"\d+", line)
            end_bucket = int(numbers[0])
            buckets.append("0")
            count = int(numbers[1])
            data.append(count)
            state = 2
        elif state == 2:
            numbers = re.findall(r"\d+", line)
            if "...)" in line:
                start_bucket = int(numbers[0])
                data.append(int(numbers[1]))
                buckets.append(f"{start_bucket}+")
                state = 3
            else:
                start_bucket = int(numbers[0])
                end_bucket = int(numbers[1])
                buckets.append(str(start_bucket))
                data.append(int(numbers[2]))

    if state == 3:
        draw_histogram(buckets, data, title)

    plt.show()
