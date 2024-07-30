# Path
KERNEL_DIR := kernel/rCore-Tutorial-v3/os

# Building
TARGET := riscv64gc-unknown-none-elf
MODE := release
KERNEL_ELF := $(KERNEL_DIR)/target/$(TARGET)/$(MODE)/os
KERNEL_BIN := $(KERNEL_ELF).bin

# BOARD
BOARD := qemu
SBI ?= rustsbi
BOOTLOADER := $(KERNEL_DIR)/../bootloader/$(SBI)-$(BOARD).bin

# KERNEL ENTRY
KERNEL_ENTRY_PA := 0x80200000

QEMU_ARGS := -machine virt \
			 -nographic \
			 -bios $(BOOTLOADER) \
			 -device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA)

run: build
	cargo run --release -- ${QEMU_ARGS}

build: env
	make -C $(KERNEL_DIR)
	cargo build --release

env:
	export LLVM_CONFIG=15

clean:
	make -C $(KERNEL_DIR) clean
	cargo clean

.PHONY: run build env clean
