#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_NO_PREALLOC 1
#define ETH_HLEN	14
/*
struct bpf_elf_map {
        __u32 type;
        __u32 size_key;
        __u32 size_value;
        __u32 max_elem;
        __u32 flags;
        __u32 id;
        __u32 pinning;
};
*/
struct keystruct
{
  __u32 prefix_len;
  __u8 ip[4];
};

#define BPF_MAP_ID_INGRESS_MAP 2
#define MAX_RULES 256
#define MIN_RULES 128
#define PIN_GLOBAL_NS           2

/*
struct bpf_elf_map SEC("maps") ingress_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .id = BPF_MAP_ID_INGRESS_MAP,
    .size_key = sizeof(struct keystruct),
    .size_value = sizeof(__u32),
    .max_elem = MAX_RULES,
    .pinning = PIN_GLOBAL_NS,
    .flags = 1,
};
*/
/*
#define BPF_TRIE_MAP(_name, _pinning, _id, _flags, _type, _key_type, _value_type, _max_entries)                                \
    struct {                                                                                       \
        __uint(type, _type);                                                                       \
        __uint(pinning, _pinning);                                                                       \
        __uint(flags, _flags);                                                                       \
        __uint(id, _id);                                                                       \
        __uint(max_entries, _max_entries);                                                         \
        __type(key, _key_type);                                                                    \
        __type(value, _value_type);                                                                \
    } _name SEC(".maps");

#define BPF_LPM(_name, _key_type, _value_type, _max_entries) \
        BPF_TRIE_MAP(_name, PIN_GLOBAL_NS, BPF_MAP_ID_INGRESS_MAP, BPF_F_NO_PREALLOC, BPF_MAP_TYPE_LPM_TRIE, _key_type, _value_type, _max_entries)

BPF_LPM(ingress_map, struct keystruct, u8, 10240);
*/
/*
struct bpf_map_def SEC("maps") ingress_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct keystruct),
    .value_size = sizeof(__u32),
    .max_entries = 100,
    .map_flags = BPF_F_NO_PREALLOC, 
};
*/
/*
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct v4_lpm_key);
	__type(value, struct v4_lpm_value);
	__uint(max_entries, 100);
	__uint(flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_map SEC(".maps");

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};
*/

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

/* TODO: Describe what this PIN_GLOBAL_NS value 2 means???
 *
 * A file is automatically created here:
 *  /sys/fs/bpf/tc/globals/egress_ifindex
 */
#define PIN_GLOBAL_NS	2
/*
struct bpf_elf_map SEC("maps") egress_ifindex = {
	.type = BPF_MAP_TYPE_ARRAY,
	.size_key = sizeof(int),
	.size_value = sizeof(int),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 1,
};
*/

struct lpm_trie_key {
    __u32 prefixlen;
    __u32 ip;
};

struct lpm_trie_val {
    __u32 protocol;
    __u32 start_port;
    __u32 end_port;
};

struct bpf_map_def_pvt SEC("maps") egress_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size =sizeof(struct lpm_trie_key),
    .value_size = sizeof(struct lpm_trie_val),
    .max_entries = 100,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning = PIN_GLOBAL_NS,
};


SEC("tc_cls")
int handle_egress(struct __sk_buff *skb)
{
	struct keystruct trie_key;
	struct lpm_trie_val *trie_val;
	int l4port = 0;
	//int htons_port = 0;
	//int ntohs_port = 0;
    void *data_end = (void *)(long)skb->data_end;
  	void *data = (void *)(long)skb->data;
  	
	struct ethhdr *ether = data;
  	if (data + sizeof(*ether) > data_end) {
    		return BPF_OK;
  	}
  	if (ether->h_proto == 0x08U) {  // htons(ETH_P_IP) -> 0x08U
    		data += sizeof(*ether);
    		struct iphdr *ip = data;
    		struct tcphdr *l4hdr = data + sizeof(struct iphdr);
    		if (data + sizeof(*ip) > data_end) {
      			return BPF_OK;
    		}
    		if (ip->version != 4) {
      			return BPF_OK;
    		}
    		if (data + sizeof(*ip) + sizeof(*l4hdr) > data_end) {
    		    return BPF_OK;
    		}

		bpf_printk("Dest addr %x", ip->daddr);
		bpf_printk("Protocol in the IP Header: %d", ip->protocol);
        bpf_printk("L4 Src Port: %d", l4hdr->source);


        l4port = (((((unsigned short)(l4hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4hdr->source) & 0xFF00) >> 8));
        //ntohs_port = (((((unsigned short)(l4hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4hdr->source) & 0xFF00) >> 8));

        bpf_printk("L4 Src Port - ntohs: %d", l4port);
        //bpf_printk("L4 Src Port - htons: %d", htons_port);
      //  bpf_printk("L4 Dest Port: %d", l4hdr->dest);
      //  bpf_printk("L4 Dest Port - be16 convert: %d", be16_to_cpu(l4hdr->dest));


/*
		if (ip->protocol == IPPROTO_TCP) {
		    struct tcphdr *l4hdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
		    l4port = l4hdr->source;
		    bpf_printk("L4 Port: %d", l4port);
		} else if (ip->protocol == IPPROTO_UDP) {
		    struct udphdr *l4hdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
		    l4port = l4hdr->source;
		}
		*/

		//bpf_printk("Port: %d", tcph->source);

		trie_key.prefix_len = 32;
		trie_key.ip[0] = ip->daddr & 0xff;
		trie_key.ip[1] = (ip->daddr >> 8) & 0xff;
		trie_key.ip[2] = (ip->daddr >> 16) & 0xff;
		trie_key.ip[3] = (ip->daddr >> 24) & 0xff;
         
		bpf_printk("0 byte %d", trie_key.ip[0]);
		bpf_printk("1 byte %d", trie_key.ip[1]);
		bpf_printk("2 byte %d", trie_key.ip[2]);
		bpf_printk("3 byte %d", trie_key.ip[3]);
		trie_val = bpf_map_lookup_elem(&egress_map, &trie_key);

		if (trie_val == NULL) {
            return BPF_DROP;
        }

        bpf_printk("Flow Protocol: %d", trie_val->protocol);
        bpf_printk("Flow Start Port: %d", trie_val->start_port);
        bpf_printk("Flow End Port: %d", trie_val->end_port);


        //if (((trie_val->protocol == ip->protocol) ||  (trie_val->protocol == 1))
        if (trie_val->protocol == ip->protocol && l4port >= trie_val->start_port
             && l4port <= trie_val->end_port) {
            bpf_printk("Protocol and Port match %d; %d", trie_val->protocol, l4port);
            return BPF_OK;
        } else {
            return BPF_DROP;
        }

		//return val == NULL ? BPF_DROP : BPF_OK;
	}
        return BPF_OK;
}

char _license[] SEC("license") = "GPL";
