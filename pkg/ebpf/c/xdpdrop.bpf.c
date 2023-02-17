#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
/*
// IPv4 addr/mask to store in the trie
struct ip4_trie_key {
	u32 prefixlen;    	// first member must be u32
	struct in_addr addr;  // rest can are arbitrary
};

// Define a longest prefix match trie.
// The key is the struct above and we ignore the value
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 128);
	__type(key, struct ip4_trie_key);
	__type(value, char);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} denylist SEC(".maps");
*/

struct bpf_map_def SEC("maps") matches = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 10,
};


struct bpf_map_def SEC("maps") blacklist = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = 10,
    .map_flags = 1, 
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} port_h SEC(".maps");

SEC("xdp")
int xdp_drop_prog(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
