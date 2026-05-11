#ifndef VM_STOWAWAY_PROTOCOL_H
#define VM_STOWAWAY_PROTOCOL_H

#include <stdint.h>

#define VMSW_MAGIC 0x57534D56u  /* 'VMSW' little-endian */

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
    VMSW_OP_QUIT             = 0xFF,
};

enum vmsw_status {
    VMSW_OK              = 0,
    VMSW_ERR_INTERNAL    = 1,
    VMSW_ERR_BAD_OP      = 2,
    VMSW_ERR_BAD_REQUEST = 3,
    VMSW_ERR_BAD_ADDR    = 4,
    VMSW_ERR_NOT_FOUND   = 5,
};

struct vmsw_hdr {
    uint32_t magic;
    uint32_t op_or_status;
    uint32_t seq;
    uint32_t flags;
    uint64_t payload_len;
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
    uint32_t count;   /* number of natural_t (uint32_t) units to return */
};

struct vmsw_thread_state_set_req {
    uint64_t tid;
    uint32_t flavor;
    uint32_t count;   /* number of natural_t units; state bytes follow */
};

struct vmsw_alloc_req {
    uint64_t size;
    int32_t  flags;
    uint32_t _pad;
};

struct vmsw_alloc_resp {
    uint64_t addr;
};

struct vmsw_dealloc_req {
    uint64_t addr;
    uint64_t size;
};

#endif
