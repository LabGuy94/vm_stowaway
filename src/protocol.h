#ifndef VM_STOWAWAY_PROTOCOL_H
#define VM_STOWAWAY_PROTOCOL_H

#include <stdint.h>

#define VMSW_MAGIC   0x57534D56u  /* 'VMSW' little-endian */
#define VMSW_VERSION 2u

enum vmsw_op {
    VMSW_OP_PING             = 0,
    VMSW_OP_READ             = 1,
    VMSW_OP_WRITE            = 2,
    VMSW_OP_RESOLVE          = 3,
    VMSW_OP_IMAGES           = 4,
    VMSW_OP_REGIONS          = 5,
    VMSW_OP_SCAN             = 6,
    VMSW_OP_DYLD_INFO        = 7,
    VMSW_OP_THREADS          = 8,
    VMSW_OP_THREAD_GET_STATE = 9,
    VMSW_OP_THREAD_SET_STATE = 10,
    VMSW_OP_ALLOCATE         = 11,
    VMSW_OP_DEALLOCATE       = 12,
    VMSW_OP_VERSION          = 13,
    VMSW_OP_CALL             = 14,
    VMSW_OP_BREAK_SET        = 15,
    VMSW_OP_BREAK_CLEAR      = 16,
    VMSW_OP_BREAK_WAIT       = 17,
    VMSW_OP_BREAK_CONT       = 18,
    VMSW_OP_QUIT             = 0xFF,
};

enum vmsw_status {
    VMSW_OK              = 0,
    VMSW_ERR_INTERNAL    = 1,
    VMSW_ERR_BAD_OP      = 2,
    VMSW_ERR_BAD_REQUEST = 3,
    VMSW_ERR_BAD_ADDR    = 4,
    VMSW_ERR_NOT_FOUND   = 5,
    VMSW_ERR_AUTH        = 6,
    VMSW_ERR_VERSION     = 7,
};

struct vmsw_hdr {
    uint32_t magic;
    uint32_t op_or_status;
    uint32_t seq;
    uint32_t flags;
    uint64_t payload_len;
};

struct vmsw_version_resp {
    uint32_t version;
    uint32_t caps;       /* bitmask, reserved */
    uint64_t pid;
};

struct vmsw_read_req   { uint64_t addr; uint64_t len; };
struct vmsw_write_req  { uint64_t addr; uint64_t len; /* data follows */ };
struct vmsw_resolve_req { uint32_t image_len; uint32_t sym_len; /* image bytes, sym bytes */ };
struct vmsw_resolve_resp { uint64_t addr; };
struct vmsw_image_entry { uint64_t base; uint64_t slide; uint32_t path_len; uint32_t _pad; /* path bytes */ };
struct vmsw_region_entry { uint64_t base; uint64_t size; uint32_t prot; uint32_t _pad; };
struct vmsw_scan_req {
    uint64_t start;
    uint64_t end;
    uint64_t plen;
    uint64_t max_hits;
    /* pattern[plen], mask[plen] follow */
};

struct vmsw_dyld_info_resp {
    uint64_t all_image_info_addr;
    uint64_t all_image_info_size;
    uint32_t all_image_info_format;
    uint32_t _pad;
};

struct vmsw_thread_entry {
    uint64_t tid;
};

struct vmsw_thread_state_req {
    uint64_t tid;
    uint32_t flavor;
    uint32_t count;
};

struct vmsw_thread_state_set_req {
    uint64_t tid;
    uint32_t flavor;
    uint32_t count;
};

struct vmsw_alloc_req {
    uint64_t size;
    int32_t  flags;
    uint32_t _pad;
};

struct vmsw_alloc_resp { uint64_t addr; };
struct vmsw_dealloc_req { uint64_t addr; uint64_t size; };

#define VMSW_CALL_MAX_ARGS 6
struct vmsw_call_req {
    uint64_t addr;
    uint32_t nargs;
    uint32_t _pad;
    uint64_t args[VMSW_CALL_MAX_ARGS];
};
struct vmsw_call_resp { uint64_t ret; };

struct vmsw_break_set_req   { uint64_t addr; };
struct vmsw_break_set_resp  { uint32_t bp_id; uint32_t _pad; };
struct vmsw_break_clear_req { uint32_t bp_id; uint32_t _pad; };
struct vmsw_break_wait_req  { int32_t timeout_ms; uint32_t _pad; };
struct vmsw_break_wait_resp { uint32_t bp_id; uint32_t _pad; uint64_t tid; uint64_t pc; };
struct vmsw_break_cont_req  { uint64_t tid; };

#endif
