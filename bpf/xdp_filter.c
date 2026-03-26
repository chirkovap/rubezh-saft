// XDPGuard - Программа фильтрации пакетов XDP/eBPF
// Высокопроизводительная фильтрация пакетов на уровне драйвера NIC с ДИНАМИЧЕСКОЙ конфигурацией

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
#define MAX_WHITELIST_ENTRIES 1000
#define MAX_RATELIMIT_ENTRIES 65536

// Ключи конфигурации для config_map
#define CFG_SYN_RATE  0
#define CFG_UDP_RATE  1
#define CFG_ICMP_RATE 2
#define CFG_ENABLED   3

// BPF Maps

// Карта конфигурации — хранит лимиты трафика (обновляется Python-ом из config.yaml)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10);
} config_map SEC(".maps");

// Карта чёрного списка IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // IP-адрес
    __type(value, __u8);   // 1 = заблокирован
    __uint(max_entries, MAX_BLACKLIST_ENTRIES);
} blacklist SEC(".maps");

// Карта белого списка IP (эти IP никогда не блокируются)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // IP-адрес
    __type(value, __u8);   // 1 = в белом списке
    __uint(max_entries, MAX_WHITELIST_ENTRIES);
} whitelist SEC(".maps");

// Карта ограничения скорости с временными метками
struct rate_info {
    __u64 pkt_count;    // Счётчик пакетов
    __u64 last_reset;   // Время последнего сброса
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);              // IP-адрес
    __type(value, struct rate_info); // Счётчик пакетов + временная метка
    __uint(max_entries, MAX_RATELIMIT_ENTRIES);
} rate_limit SEC(".maps");

// Карта статистики
struct stats {
    __u64 packets_total;    // Всего пакетов
    __u64 packets_dropped;  // Заблокировано пакетов
    __u64 packets_passed;   // Пропущено пакетов
    __u64 bytes_total;      // Всего байт
    __u64 bytes_dropped;    // Заблокировано байт
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

// Вспомогательная функция: получить значение конфигурации
static __always_inline __u64 get_config(__u32 key, __u64 default_val) {
    __u64 *val = bpf_map_lookup_elem(&config_map, &key);
    return val ? *val : default_val;
}

// Вспомогательная функция для разбора заголовков пакета
static __always_inline int parse_packet(struct xdp_md *ctx,
                                         struct ethhdr **eth,
                                         struct iphdr **ip) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Разобрать заголовок Ethernet
    *eth = data;
    if ((void *)(*eth + 1) > data_end)
        return -1;

    // Проверить, что это IPv4
    if ((*eth)->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    // Разобрать заголовок IP
    *ip = (void *)(*eth + 1);
    if ((void *)(*ip + 1) > data_end)
        return -1;

    return 0;
}

// Обновить статистику
static __always_inline void update_stats(__u32 action, __u64 bytes) {
    __u32 key = 0;
    struct stats *stat = bpf_map_lookup_elem(&stats_map, &key);
    if (!stat) return;

    __sync_fetch_and_add(&stat->packets_total, 1);
    __sync_fetch_and_add(&stat->bytes_total, bytes);

    if (action == XDP_DROP) {
        __sync_fetch_and_add(&stat->packets_dropped, 1);
        __sync_fetch_and_add(&stat->bytes_dropped, bytes);
    } else if (action == XDP_PASS) {
        __sync_fetch_and_add(&stat->packets_passed, 1);
    }
}

// Проверить лимит трафика с временным окном (1 секунда)
static __always_inline int check_rate_limit(__u32 src_ip, __u8 protocol) {
    struct rate_info *rate = bpf_map_lookup_elem(&rate_limit, &src_ip);
    __u64 now          = bpf_ktime_get_ns();
    __u64 one_sec_ns   = 1000000000ULL; // 1 секунда в наносекундах

    // Получить лимит из конфигурации в зависимости от протокола
    __u64 rate_limit_pps;
    if (protocol == IPPROTO_TCP) {
        rate_limit_pps = get_config(CFG_SYN_RATE, 1000);  // По умолчанию 1000 пакетов/с
    } else if (protocol == IPPROTO_UDP) {
        rate_limit_pps = get_config(CFG_UDP_RATE, 500);   // По умолчанию 500 пакетов/с
    } else if (protocol == IPPROTO_ICMP) {
        rate_limit_pps = get_config(CFG_ICMP_RATE, 100);  // По умолчанию 100 пакетов/с
    } else {
        return 0; // Другие протоколы пропускаем
    }

    if (rate) {
        // Проверить, истекло ли окно (прошла ли 1 секунда)
        if (now - rate->last_reset > one_sec_ns) {
            // Сбросить счётчик для нового окна
            rate->pkt_count  = 1;
            rate->last_reset = now;
        } else {
            // Увеличить счётчик
            rate->pkt_count++;
            // Проверить, превышен ли лимит
            if (rate->pkt_count > rate_limit_pps) {
                return 1; // Лимит превышен — блокировать
            }
        }
    } else {
        // Первый пакет с этого IP — инициализировать
        struct rate_info new_rate = {
            .pkt_count  = 1,
            .last_reset = now
        };
        bpf_map_update_elem(&rate_limit, &src_ip, &new_rate, BPF_ANY);
    }

    return 0; // Лимит не превышен
}

SEC("xdp")
int xdp_filter_func(struct xdp_md *ctx) {
    struct ethhdr *eth;
    struct iphdr  *ip;
    __u32  src_ip;
    __u8  *whitelisted;
    __u8  *blocked;
    __u32  action = XDP_PASS;
    __u64  bytes  = (__u64)(ctx->data_end - ctx->data);

    // Разобрать заголовки пакета
    if (parse_packet(ctx, &eth, &ip) < 0) {
        // Не IPv4 или повреждённый пакет — пропустить
        return XDP_PASS;
    }

    src_ip = ip->saddr;

    // Проверить, включена ли защита
    __u64 enabled = get_config(CFG_ENABLED, 1);
    if (!enabled) {
        update_stats(XDP_PASS, bytes);
        return XDP_PASS;
    }

    // Сначала проверить белый список — IP из него обходят все проверки
    whitelisted = bpf_map_lookup_elem(&whitelist, &src_ip);
    if (whitelisted && *whitelisted) {
        update_stats(XDP_PASS, bytes);
        return XDP_PASS;
    }

    // Проверить чёрный список IP
    blocked = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (blocked && *blocked) {
        action = XDP_DROP;
        update_stats(action, bytes);
        return XDP_DROP;
    }

    // Проверка лимита трафика (по протоколу)
    if (check_rate_limit(src_ip, ip->protocol)) {
        action = XDP_DROP;
        update_stats(action, bytes);
        return XDP_DROP;
    }

    // Пакет прошёл все проверки
    update_stats(action, bytes);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
