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

CONTROLLER_SRC := src/controller.c src/patcher.c
PAYLOAD_SRC    := payload/payload.c
CLI_SRC        := cli/vm_stowaway.c

CONTROLLER_OBJ := $(CONTROLLER_SRC:%.c=$(BUILD)/%.o)
PAYLOAD_OBJ    := $(PAYLOAD_SRC:%.c=$(BUILD)/%.o)
CLI_OBJ        := $(CLI_SRC:%.c=$(BUILD)/%.o)

LIB_STATIC  := $(BUILD)/lib$(NAME).a
LIB_DYNAMIC := $(BUILD)/lib$(NAME).dylib
PAYLOAD_LIB := $(BUILD)/lib$(NAME)_payload.dylib
CLI_BIN     := $(BUILD)/$(NAME)

EXAMPLES := $(BUILD)/examples/target $(BUILD)/examples/controller_example

.PHONY: all clean install test
all: $(LIB_STATIC) $(LIB_DYNAMIC) $(PAYLOAD_LIB) $(CLI_BIN) $(EXAMPLES)

# Compile .c -> .o under build/
$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Static library: controller + patcher (no payload; the payload runs in the
# target). Use libtool (Apple's) instead of ar so we get a proper fat static
# archive without ranlib warnings.
$(LIB_STATIC): $(CONTROLLER_OBJ)
	@mkdir -p $(dir $@)
	libtool -static -o $@ $^ 2>/dev/null || $(AR) rcs $@ $^

# Shared controller library
$(LIB_DYNAMIC): $(CONTROLLER_OBJ)
	@mkdir -p $(dir $@)
	$(CC) -dynamiclib -install_name @rpath/lib$(NAME).dylib \
	    -current_version $(VERSION) -compatibility_version 1.0.0 \
	    $(LDFLAGS) $^ -o $@
	codesign --force --sign - $@

# The injected payload dylib (lives inside the target process)
$(PAYLOAD_LIB): $(PAYLOAD_OBJ)
	@mkdir -p $(dir $@)
	$(CC) -dynamiclib -install_name @rpath/lib$(NAME)_payload.dylib \
	    $(LDFLAGS) -lpthread $^ -o $@
	codesign --force --sign - $@

# CLI links the static library so the binary is self-contained
$(CLI_BIN): $(CLI_OBJ) $(LIB_STATIC)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(CLI_OBJ) $(LIB_STATIC) -o $@
	codesign --force --sign - $@

# Examples: compile with default visibility so dlsym can find globals.
# -headerpad_max_install_names gives ~16K of slack in the Mach-O header so
# `vm_stowaway patch` has room to insert an LC_LOAD_DYLIB. Real apps usually
# have plenty of header padding; tiny test binaries often don't.
$(BUILD)/examples/target: examples/target.c
	@mkdir -p $(dir $@)
	$(CC) $(EXAMPLE_CFLAGS) $(LDFLAGS) -Wl,-headerpad_max_install_names $< -o $@
	codesign --force --sign - $@

$(BUILD)/examples/controller_example: examples/controller_example.c $(LIB_STATIC)
	@mkdir -p $(dir $@)
	$(CC) $(EXAMPLE_CFLAGS) $(LDFLAGS) $< $(LIB_STATIC) -o $@
	codesign --force --sign - $@

install: all
	install -d $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/include \
	           $(DESTDIR)$(PREFIX)/bin
	install -m 0644 $(LIB_STATIC) $(LIB_DYNAMIC) $(PAYLOAD_LIB) $(DESTDIR)$(PREFIX)/lib/
	install -m 0644 include/$(NAME).h $(DESTDIR)$(PREFIX)/include/
	install -m 0755 $(CLI_BIN) $(DESTDIR)$(PREFIX)/bin/

test: all
	scripts/smoke.sh $(BUILD)

clean:
	rm -rf $(BUILD)
