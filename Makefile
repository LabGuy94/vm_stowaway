# vm_stowaway: simple memory read/write via dylib injection on macOS

NAME       := vm_stowaway
VERSION    := 0.1.0

PREFIX     ?= /usr/local
ARCHS      ?= arm64 x86_64
BUILD      ?= build

ARCHFLAGS  := $(addprefix -arch ,$(ARCHS))
COMMON_CFLAGS := -std=c11 -Wall -Wextra -Wpedantic \
                 -Wno-gnu-zero-variadic-macro-arguments \
                 -Iinclude -Isrc $(ARCHFLAGS) -mmacosx-version-min=11.0
CFLAGS     ?= -O2 -g
CFLAGS     += $(COMMON_CFLAGS) -fvisibility=hidden -fPIC
EXAMPLE_CFLAGS := -O2 -g $(COMMON_CFLAGS)
LDFLAGS    += $(ARCHFLAGS) -mmacosx-version-min=11.0

CONTROLLER_SRC := src/controller.c
PAYLOAD_SRC    := payload/payload.c

CONTROLLER_OBJ := $(CONTROLLER_SRC:%.c=$(BUILD)/%.o)
PAYLOAD_OBJ    := $(PAYLOAD_SRC:%.c=$(BUILD)/%.o)

LIB_STATIC  := $(BUILD)/lib$(NAME).a
LIB_DYNAMIC := $(BUILD)/lib$(NAME).dylib
PAYLOAD_LIB := $(BUILD)/lib$(NAME)_payload.dylib

EXAMPLES := $(BUILD)/examples/target $(BUILD)/examples/controller_example

.PHONY: all clean install test
all: $(LIB_STATIC) $(LIB_DYNAMIC) $(PAYLOAD_LIB) $(EXAMPLES)

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_STATIC): $(CONTROLLER_OBJ)
	@mkdir -p $(dir $@)
	libtool -static -o $@ $^ 2>/dev/null || $(AR) rcs $@ $^

$(LIB_DYNAMIC): $(CONTROLLER_OBJ)
	@mkdir -p $(dir $@)
	$(CC) -dynamiclib -install_name @rpath/lib$(NAME).dylib \
	    -current_version $(VERSION) -compatibility_version 1.0.0 \
	    $(LDFLAGS) $^ -o $@
	codesign --force --sign - $@

$(PAYLOAD_LIB): $(PAYLOAD_OBJ)
	@mkdir -p $(dir $@)
	$(CC) -dynamiclib -install_name @rpath/lib$(NAME)_payload.dylib \
	    $(LDFLAGS) -lpthread $^ -o $@
	codesign --force --sign - $@

# Examples: compile with default visibility so dlsym can find globals.
$(BUILD)/examples/target: examples/target.c
	@mkdir -p $(dir $@)
	$(CC) $(EXAMPLE_CFLAGS) $(LDFLAGS) -Wl,-headerpad_max_install_names $< -o $@
	codesign --force --sign - $@

$(BUILD)/examples/controller_example: examples/controller_example.c $(LIB_STATIC)
	@mkdir -p $(dir $@)
	$(CC) $(EXAMPLE_CFLAGS) $(LDFLAGS) $< $(LIB_STATIC) -o $@
	codesign --force --sign - $@

install: all
	install -d $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/include
	install -m 0644 $(LIB_STATIC) $(LIB_DYNAMIC) $(PAYLOAD_LIB) $(DESTDIR)$(PREFIX)/lib/
	install -m 0644 include/$(NAME).h $(DESTDIR)$(PREFIX)/include/

test: all
	scripts/smoke.sh $(BUILD)

clean:
	rm -rf $(BUILD)
