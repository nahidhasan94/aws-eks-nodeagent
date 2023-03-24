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
#define BPF_F_INDEX_MASK 0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK
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

struct conntrack_key {
   __u32 src_ip;
   __u16 src_port;
   __u32 dest_ip;
   __u16 dest_port;
   __u8  protocol;
};

struct conntrack_value {
   __u32 val;
};

struct data_t {
    __u32 src_ip;
    __u32  src_port;
    __u32  dest_ip;
    __u32  dest_port;
    __u32 protocol;
    __u32 verdict;
};

struct bpf_map_def_pvt SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

struct bpf_map_def_pvt SEC("maps") ingress_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size =sizeof(struct lpm_trie_key),
    .value_size = sizeof(struct lpm_trie_val),
    .max_entries = 100,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") conntrack_ingress_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size =sizeof(struct conntrack_key),
    .value_size = sizeof(struct conntrack_value),
    .max_entries = 100,
    .pinning = PIN_GLOBAL_NS,
};

/*
static __always_inline u32 flow_status(struct nf_conn *ct) {
  u32 status;
  bpf_probe_read(&status, sizeof(status), &ct->status);
  return status;
}

static __always_inline void get_conntrack_tuple(struct conntrack_cache *data, struct nf_conn *ct) {

  struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
  bpf_probe_read(&tuplehash, sizeof(tuplehash), &ct->tuplehash);

  bpf_probe_read(&data->proto, sizeof(data->proto), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum);

  bpf_probe_read(&data->srcaddr, sizeof(data->srcaddr), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3);
  bpf_probe_read(&data->dstaddr, sizeof(data->dstaddr), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3);

  bpf_probe_read(&data->src_port, sizeof(data->src_port), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all);
  bpf_probe_read(&data->dst_port, sizeof(data->dst_port), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all);
}

SEC("kprobe/__nf_conntrack_hash_insert")
int conn_insert(struct pt_regs *ctx) {

  	u64 ts = bpf_ktime_get_ns();

  	struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);

   	if (flow_status(ct) == 0)
   	 	return 0;


	bpf_map_update_elem(&flow_origin, &ct, &ts, BPF_NOEXIST);
	return 0;
}


SEC("kprobe/nf_ct_delete")
int conn_del(struct pt_regs *ctx) {

  struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);
  struct conntrack_cache conn_data;
  get_conntrack_tuple(&conn_data, ct);

  //Use conn_data to compare sport/dport/sip/dip/proto

  bpf_map_delete_elem(&flow_origin, &ct);

  return 0;
}
*/

SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb)
{
	struct keystruct trie_key;
	struct lpm_trie_val *trie_val;
	struct conntrack_key flow_key;
	struct conntrack_value flow_val;
	struct conntrack_key reverse_flow_key;
    struct conntrack_value reverse_flow_val;
	int l4_src_port = 0;
	int l4_dst_port = 0;
    void *data_end = (void *)(long)skb->data_end;
  	void *data = (void *)(long)skb->data;


  	memset(&flow_key, 0, sizeof(flow_key));
  	memset(&flow_val, 0, sizeof(flow_val));
  	memset(&reverse_flow_key, 0, sizeof(reverse_flow_key));
    memset(&reverse_flow_val, 0, sizeof(reverse_flow_val));
  	
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


		bpf_printk("Src addr %x", ip->saddr);
		bpf_printk("Protocol in the IP Header: %d", ip->protocol);
		bpf_printk("L4 Src Port: %d", l4hdr->source);

        l4_src_port = (((((unsigned short)(l4hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4hdr->source) & 0xFF00) >> 8));
        l4_dst_port = (((((unsigned short)(l4hdr->dest) & 0xFF)) << 8) | (((unsigned short)(l4hdr->dest) & 0xFF00) >> 8));


        bpf_printk("conv: L4 Src Port: %d", l4_src_port);
        bpf_printk("conv: L4 Dest Port: %d", l4_dst_port);


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

		trie_key.prefix_len = 32;
		trie_key.ip[0] = ip->saddr & 0xff;
		trie_key.ip[1] = (ip->saddr >> 8) & 0xff;
		trie_key.ip[2] = (ip->saddr >> 16) & 0xff;
		trie_key.ip[3] = (ip->saddr >> 24) & 0xff;


        flow_key.src_ip = ip->saddr;
        flow_key.src_port = l4_src_port;
        flow_key.dest_ip = ip->daddr;
        flow_key.dest_port = l4_dst_port;
        flow_key.protocol = ip->protocol;

        struct data_t evt = {};
        evt.src_ip = flow_key.src_ip;
        evt.src_port = flow_key.src_port;
        evt.dest_ip = flow_key.dest_ip;
        evt.dest_port = flow_key.dest_port;
        evt.protocol = flow_key.protocol; 

        flow_val.val = 0;

        //Check if it's an existing flow
        trie_val = bpf_map_lookup_elem(&conntrack_ingress_map, &flow_key);
        if (trie_val != NULL) {
           bpf_printk("Existing Flow: Src IP:Src Port; Protocol: %d, %d, %d",
           (__u32)ip->saddr, l4_src_port, ip->protocol);
           return BPF_OK;
        }

        //Check for the reverse flow entry in the conntrack table
        reverse_flow_key.src_ip = ip->daddr;
        reverse_flow_key.src_port = l4_dst_port;
        reverse_flow_key.dest_ip = ip->saddr;
        reverse_flow_key.dest_port = l4_src_port;
        reverse_flow_key.protocol = ip->protocol;

        reverse_flow_val.val = 0;

        //Check if it's a response packet
        trie_val = bpf_map_lookup_elem(&conntrack_ingress_map, &reverse_flow_key);
        if (trie_val != NULL) {
           bpf_printk("Response Flow: Src IP:Src Port; Protocol: %d, %d, %d",
           (__u32)ip->saddr, l4_src_port, ip->protocol);
           return BPF_OK;
        }

		trie_val = bpf_map_lookup_elem(&ingress_map, &trie_key);
		if (trie_val == NULL) {
            return BPF_DROP;
        }

        bpf_printk("Flow Protocol: %d", trie_val->protocol);
        bpf_printk("Flow Start Port: %d", trie_val->start_port);
        bpf_printk("Flow End Port: %d", trie_val->end_port);

        __u64 flags = BPF_F_CURRENT_CPU;

        if (trie_val->protocol == ip->protocol && l4_src_port >= trie_val->start_port
             && l4_src_port <= trie_val->end_port) {
            bpf_printk("ACCEPT - Src IP:Src Port; Protocol: %d, %d, %d",
            (__u32)ip->saddr, l4_src_port, ip->protocol);
            //Inject in to conntrack map
            bpf_map_update_elem(&conntrack_ingress_map, &flow_key, &flow_val, 0); // 0 - BPF_ANY
            evt.verdict = 1;
            bpf_perf_event_output(skb, &events, flags, &evt, sizeof(evt));
            return BPF_OK;
        } else {
            bpf_printk("DENY - Src IP:Src Port; Protocol: %d, %d, %d",
            (__u32)ip->saddr, l4_src_port, ip->protocol);
            evt.verdict = 0;
            bpf_perf_event_output(skb, &events, flags, &evt, sizeof(evt));
            return BPF_DROP;
        }
        //__u64 flags = BPF_F_CURRENT_CPU;
       // bpf_perf_event_output(skb, &events, flags, &evt, sizeof(evt));
	}
        return BPF_OK;
}

char _license[] SEC("license") = "GPL";
