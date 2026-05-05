CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE
LDFLAGS := -lpthread

TARGET  := packforge
SRC_DIR := src
BUILD   := build

SRCS := \
    $(SRC_DIR)/main.c \
    $(SRC_DIR)/net/checksum.c \
    $(SRC_DIR)/net/ip.c \
    $(SRC_DIR)/net/tcp.c \
    $(SRC_DIR)/net/udp.c \
    $(SRC_DIR)/net/icmp.c \
    $(SRC_DIR)/net/arp.c \
    $(SRC_DIR)/forge/forge.c \
    $(SRC_DIR)/sniff/sniffer.c \
    $(SRC_DIR)/sniff/dissect.c \
    $(SRC_DIR)/util/iface.c \
    $(SRC_DIR)/util/pcap.c

OBJS := $(patsubst $(SRC_DIR)/%.c, $(BUILD)/%.o, $(SRCS))

.PHONY: all clean install uninstall

all: $(BUILD)/$(TARGET)

$(BUILD)/$(TARGET): $(OBJS)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "  ✓  Built: $(BUILD)/$(TARGET)"
	@echo "  ▸  Run as root: sudo $(BUILD)/$(TARGET) --help"
	@echo ""

$(BUILD)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

clean:
	rm -rf $(BUILD)

install: $(BUILD)/$(TARGET)
	install -m 755 $(BUILD)/$(TARGET) /usr/local/bin/$(TARGET)
	@echo "Installed to /usr/local/bin/$(TARGET)"

uninstall:
	rm -f /usr/local/bin/$(TARGET)
