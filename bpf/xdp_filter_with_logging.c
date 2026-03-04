// XDPGuard - XDP/eBPF DDoS Filter with Packet Logging
// High-performance packet filtering with detailed logging

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BLACKLIST_ENTRIES 10000
#define MAX_RATELIMIT_ENTRIES 65536
#define SAMPLE_RATE 100  // Log 1 out of every 100 normal packets

// Packet log entry structure
struct packet_log {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;       // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP
    __u8 action;         // XDP_PASS=2, XDP_DROP=1
    __u8 reason;         // 0=normal, 1=blacklist, 2=rate_limit, 3=syn_flood
    __u8 flags;          // TCP flags if applicable
    __u32 packet_size;
    __u64 timestamp;
};

// BPF Maps
// IP Blacklist map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);      // IP address
    __type(value, __u8);     // 1 = blocked
    __uint(max_entries, MAX_BLACKLIST_ENTRIES);
} blacklist SEC(".maps");

// Rate limiting map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_RATELIMIT_ENTRIES);
} rate_limit SEC(".maps");

// Ring buffer for packet logs
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB ring buffer
} packet_logs SEC(".maps");

// Statistics map
struct stats {
    __u64 packets_total;
    __u64 packets_dropped;
    __u64 packets_passed;
    __u64 bytes_total;
    __u64 bytes_dropped;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

// Sample counter for rate limiting logs
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} sample_counter SEC(".maps");

// Helper to get current timestamp
static __always_inline __u64 get_timestamp(void) {
    return bpf_ktime_get_ns();
}

// Helper to log packet
static __always_inline void log_packet(__u32 src_ip, __u32 dst_ip,
                                       __u16 src_port, __u16 dst_port,
                                       __u8 protocol, __u8 action,
                                       __u8 reason, __u8 flags,
                                       __u32 packet_size) {
    struct packet_log *log;
    
    log = bpf_ringbuf_reserve(&packet_logs, sizeof(*log), 0);
    if (!log)
        return;
    
    log->src_ip = src_ip;
    log->dst_ip = dst_ip;
    log->src_port = src_port;
    log->dst_port = dst_port;
    log->protocol = protocol;
    log->action = action;
    log->reason = reason;
    log->flags = flags;
    log->packet_size = packet_size;
    log->timestamp = get_timestamp();
    
    bpf_ringbuf_submit(log, 0);
}

// Should we sample this packet?
static __always_inline int should_sample(void) {
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&sample_counter, &key);
    
    if (!counter) {
        __u64 init = 0;
        bpf_map_update_elem(&sample_counter, &key, &init, BPF_ANY);
        return 1;
    }
    
    __u64 val = __sync_fetch_and_add(counter, 1);
    return (val % SAMPLE_RATE) == 0;
}

// Parse packet and extract info
static __always_inline int parse_packet_info(struct xdp_md *ctx,
                                             __u32 *src_ip, __u32 *dst_ip,
                                             __u16 *src_port, __u16 *dst_port,
                                             __u8 *protocol, __u8 *tcp_flags) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
    
    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;
    *src_port = 0;
    *dst_port = 0;
    *tcp_flags = 0;
    
    // Parse transport layer
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return 0;
        
        *src_port = bpf_ntohs(tcp->source);
        *dst_port = bpf_ntohs(tcp->dest);
        
        // Extract TCP flags
        if (tcp->syn) *tcp_flags |= 0x02;
        if (tcp->ack) *tcp_flags |= 0x10;
        if (tcp->fin) *tcp_flags |= 0x01;
        if (tcp->rst) *tcp_flags |= 0x04;
        
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return 0;
        
        *src_port = bpf_ntohs(udp->source);
        *dst_port = bpf_ntohs(udp->dest);
    }
    
    return 0;
}

// Update statistics
static __always_inline void update_stats(__u32 action, __u64 bytes) {
    __u32 key = 0;
    struct stats *stat = bpf_map_lookup_elem(&stats_map, &key);
    
    if (!stat)
        return;

    __sync_fetch_and_add(&stat->packets_total, 1);
    __sync_fetch_and_add(&stat->bytes_total, bytes);

    if (action == XDP_DROP) {
        __sync_fetch_and_add(&stat->packets_dropped, 1);
        __sync_fetch_and_add(&stat->bytes_dropped, bytes);
    } else if (action == XDP_PASS) {
        __sync_fetch_and_add(&stat->packets_passed, 1);
    }
}

SEC("xdp")
int xdp_filter_func(struct xdp_md *ctx) {
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;
    __u8 protocol, tcp_flags;
    __u8 *blocked;
    __u64 *pkt_count;
    __u32 action = XDP_PASS;
    __u8 reason = 0;  // 0=normal
    __u64 bytes = (__u64)(ctx->data_end - ctx->data);
    int should_log = 0;

    // Parse packet
    if (parse_packet_info(ctx, &src_ip, &dst_ip, &src_port, &dst_port, 
                         &protocol, &tcp_flags) < 0) {
        return XDP_PASS;
    }

    // Check IP blacklist
    blocked = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (blocked && *blocked) {
        action = XDP_DROP;
        reason = 1;  // blacklist
        should_log = 1;  // Always log blocked packets
        
        log_packet(src_ip, dst_ip, src_port, dst_port, protocol,
                  action, reason, tcp_flags, bytes);
        
        update_stats(action, bytes);
        return XDP_DROP;
    }

    // Rate limiting check
    pkt_count = bpf_map_lookup_elem(&rate_limit, &src_ip);
    if (pkt_count) {
        __sync_fetch_and_add(pkt_count, 1);
        
        if (*pkt_count > 1000) {
            action = XDP_DROP;
            reason = 2;  // rate_limit
            should_log = 1;
            
            // Only log every 100th rate-limited packet to avoid spam
            if ((*pkt_count % 100) == 0) {
                log_packet(src_ip, dst_ip, src_port, dst_port, protocol,
                          action, reason, tcp_flags, bytes);
            }
            
            update_stats(action, bytes);
            return XDP_DROP;
        }
    } else {
        // First packet from this IP - always log
        __u64 init_count = 1;
        bpf_map_update_elem(&rate_limit, &src_ip, &init_count, BPF_ANY);
        should_log = 1;
    }

    // Sample normal traffic for visibility
    if (!should_log && should_sample()) {
        should_log = 1;
    }

    // Log packet if needed
    if (should_log) {
        log_packet(src_ip, dst_ip, src_port, dst_port, protocol,
                  action, reason, tcp_flags, bytes);
    }

    update_stats(action, bytes);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
