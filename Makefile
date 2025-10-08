# compile ebpf program

BUILD_DIR = build
TARGET := func_perf

all: $(BUILD_DIR)/$(TARGET).bpf.o $(BUILD_DIR)/$(TARGET).bpf.skel.h $(BUILD_DIR)/$(TARGET) showevtinfo

$(BUILD_DIR)/vmlinux.h:
	@mkdir -p $(BUILD_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD_DIR)/%.bpf.o: %.bpf.c $(BUILD_DIR)/vmlinux.h
	@mkdir -p $(BUILD_DIR)
	clang -Wall -target bpf -O2 -g -I$(BUILD_DIR) -c $< -o $@

$(BUILD_DIR)/%.bpf.skel.h: $(BUILD_DIR)/%.bpf.o
	@echo "Generating skeleton header for $<"
	bpftool gen skeleton $< > $@

$(BUILD_DIR)/%: %.c $(BUILD_DIR)/%.bpf.skel.h
	@mkdir -p $(BUILD_DIR)
	clang -Wall -O2 -g -I$(BUILD_DIR) -o $@ $< -lbpf -lpfm

showevtinfo: showevtinfo.c
	clang -Wall -O2 -g -o $(BUILD_DIR)/$@ $< -lpfm

clean:
	rm -rf $(BUILD_DIR)

.PHONY: clean
