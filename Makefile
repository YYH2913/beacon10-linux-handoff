# SPDX-License-Identifier: GPL-2.0-only
OUT ?= build
CC ?= cc
CROSS_COMPILE ?= aarch64-linux-gnu-
CFLAGS ?= -Os -Wall -Wextra -Werror
SRC := tools/beacon10/handoff
COMMON := $(SRC)/format.c $(SRC)/sha256.c $(SRC)/storage.c
HEADERS := $(wildcard $(SRC)/*.h)
export PYTHONDONTWRITEBYTECODE := 1

.PHONY: all host-tools arm64-tools check check-layout
all: host-tools
host-tools: $(OUT)/host/b10-loader $(OUT)/host/b10-install
arm64-tools: $(OUT)/arm64/b10-loader $(OUT)/arm64/b10-install $(OUT)/arm64/b10-jump $(OUT)/arm64/b10-stage-status

$(OUT)/host $(OUT)/arm64:
	mkdir -p $@

$(OUT)/host/b10-loader: $(SRC)/loader.c $(COMMON) $(HEADERS) | $(OUT)/host
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@

$(OUT)/host/b10-install: $(SRC)/install-main.c $(SRC)/install.c $(COMMON) $(HEADERS) | $(OUT)/host
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@

$(OUT)/arm64/b10-loader: $(SRC)/loader.c $(COMMON) $(HEADERS) | $(OUT)/arm64
	$(CROSS_COMPILE)gcc $(CFLAGS) -static $(filter %.c,$^) -o $@

$(OUT)/arm64/b10-install: $(SRC)/install-main.c $(SRC)/install.c $(COMMON) $(HEADERS) | $(OUT)/arm64
	$(CROSS_COMPILE)gcc $(CFLAGS) -static $(filter %.c,$^) -o $@

$(OUT)/arm64/b10-jump: $(SRC)/jump.c $(HEADERS) | $(OUT)/arm64
	$(CROSS_COMPILE)gcc $(CFLAGS) -static $(filter %.c,$^) -o $@

$(OUT)/arm64/b10-stage-status: $(SRC)/stage-status.c $(HEADERS) | $(OUT)/arm64
	$(CROSS_COMPILE)gcc $(CFLAGS) -static $(filter %.c,$^) -o $@

check: check-layout

check-layout:
	python3 -B tools/beacon10/storage-layout.py
