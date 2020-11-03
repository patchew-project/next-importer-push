#include <stddef.h>
#include <stdbool.h>
#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <linux/udp.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <linux/virtio_net.h>

/*
 * Prepare:
 * Requires llvm, clang, python3 with pyelftools, linux kernel tree
 *
 * Build tun_rss_steering.h:
 * make -f Mefile.ebpf clean all
 */

#define INDIRECTION_TABLE_SIZE 128
#define HASH_CALCULATION_BUFFER_SIZE 36

struct rss_config_t {
    __u8 redirect;
    __u8 populate_hash;
    __u32 hash_types;
    __u16 indirections_len;
    __u16 default_queue;
};

struct toeplitz_key_data_t {
    __u32 leftmost_32_bits;
    __u8 next_byte[HASH_CALCULATION_BUFFER_SIZE];
};

struct packet_hash_info_t {
    __u8 is_ipv4;
    __u8 is_ipv6;
    __u8 is_udp;
    __u8 is_tcp;
    __u8 is_ipv6_ext_src;
    __u8 is_ipv6_ext_dst;

    __u16 src_port;
    __u16 dst_port;

    union {
        struct {
            __be32 in_src;
            __be32 in_dst;
        };

        struct {
            struct in6_addr in6_src;
            struct in6_addr in6_dst;
            struct in6_addr in6_ext_src;
            struct in6_addr in6_ext_dst;
        };
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rss_config_t);
    __uint(max_entries, 1);
} tap_rss_map_configurations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct toeplitz_key_data_t);
    __uint(max_entries, 1);
} tap_rss_map_toeplitz_key SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u16);
    __uint(max_entries, INDIRECTION_TABLE_SIZE);
} tap_rss_map_indirection_table SEC(".maps");


static inline void net_rx_rss_add_chunk(__u8 *rss_input, size_t *bytes_written,
                                        const void *ptr, size_t size) {
    __builtin_memcpy(&rss_input[*bytes_written], ptr, size);
    *bytes_written += size;
}

static inline
void net_toeplitz_add(__u32 *result,
                      __u8 *input,
                      __u32 len
        , struct toeplitz_key_data_t *key) {

    __u32 accumulator = *result;
    __u32 leftmost_32_bits = key->leftmost_32_bits;
    __u32 byte;

    for (byte = 0; byte < HASH_CALCULATION_BUFFER_SIZE; byte++) {
        __u8 input_byte = input[byte];
        __u8 key_byte = key->next_byte[byte];
        __u8 bit;

        for (bit = 0; bit < 8; bit++) {
            if (input_byte & (1 << 7)) {
                accumulator ^= leftmost_32_bits;
            }

            leftmost_32_bits =
                    (leftmost_32_bits << 1) | ((key_byte & (1 << 7)) >> 7);

            input_byte <<= 1;
            key_byte <<= 1;
        }
    }

    *result = accumulator;
}


static inline int ip6_extension_header_type(__u8 hdr_type)
{
    switch (hdr_type) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_FRAGMENT:
    case IPPROTO_ICMPV6:
    case IPPROTO_NONE:
    case IPPROTO_DSTOPTS:
    case IPPROTO_MH:
        return 1;
    default:
        return 0;
    }
}
/*
 * According to https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
 * we suspect that there are would be no more than 11 extensions in IPv6 header,
 * also there is 27 TLV options for Destination and Hop-by-hop extensions.
 * Need to choose reasonable amount of maximum extensions/options we may check to find
 * ext src/dst.
 */
#define IP6_EXTENSIONS_COUNT 11
#define IP6_OPTIONS_COUNT 30

static inline void parse_ipv6_ext(struct __sk_buff *skb,
        struct packet_hash_info_t *info,
        __u8 *l4_protocol, size_t *l4_offset)
{
    if (!ip6_extension_header_type(*l4_protocol)) {
        return;
    }

    struct ipv6_opt_hdr ext_hdr = {};

    for (unsigned int i = 0; i < IP6_EXTENSIONS_COUNT; ++i) {

        bpf_skb_load_bytes_relative(skb, *l4_offset, &ext_hdr,
                                    sizeof(ext_hdr), BPF_HDR_START_NET);

        if (*l4_protocol == IPPROTO_ROUTING) {
            struct ipv6_rt_hdr ext_rt = {};

            bpf_skb_load_bytes_relative(skb, *l4_offset, &ext_rt,
                                        sizeof(ext_rt), BPF_HDR_START_NET);

            if ((ext_rt.type == IPV6_SRCRT_TYPE_2) &&
                    (ext_rt.hdrlen == sizeof(struct in6_addr) / 8) &&
                    (ext_rt.segments_left == 1)) {

                bpf_skb_load_bytes_relative(skb,
                    *l4_offset + offsetof(struct rt2_hdr, addr),
                    &info->in6_ext_dst, sizeof(info->in6_ext_dst),
                    BPF_HDR_START_NET);

                info->is_ipv6_ext_dst = 1;
            }

        } else if (*l4_protocol == IPPROTO_DSTOPTS) {
            struct ipv6_opt_t {
                __u8 type;
                __u8 length;
            } __attribute__((packed)) opt = {};

            size_t opt_offset = sizeof(ext_hdr);

            for (unsigned int j = 0; j < IP6_OPTIONS_COUNT; ++j) {
                bpf_skb_load_bytes_relative(skb, *l4_offset + opt_offset,
                                        &opt, sizeof(opt), BPF_HDR_START_NET);

                opt_offset += (opt.type == IPV6_TLV_PAD1) ?
                        1 : opt.length + sizeof(opt);

                if (opt_offset + 1 >= ext_hdr.hdrlen * 8) {
                    break;
                }

                if (opt.type == IPV6_TLV_HAO) {
                    bpf_skb_load_bytes_relative(skb,
                        *l4_offset + opt_offset + offsetof(struct ipv6_destopt_hao, addr),
                        &info->is_ipv6_ext_src, sizeof(info->is_ipv6_ext_src),
                        BPF_HDR_START_NET);

                    info->is_ipv6_ext_src = 1;
                    break;
                }
            }
        }

        *l4_protocol = ext_hdr.nexthdr;
        *l4_offset += (ext_hdr.hdrlen + 1) * 8;

        if (!ip6_extension_header_type(ext_hdr.nexthdr)) {
            return;
        }
    }
}

static inline void parse_packet(struct __sk_buff *skb,
        struct packet_hash_info_t *info)
{
    if (!info || !skb) {
        return;
    }

    size_t l4_offset = 0;
    __u8 l4_protocol = 0;
    __u16 l3_protocol = __be16_to_cpu(skb->protocol);

    if (l3_protocol == ETH_P_IP) {
        info->is_ipv4 = 1;

        struct iphdr ip = {};
        bpf_skb_load_bytes_relative(skb, 0, &ip, sizeof(ip),
                                    BPF_HDR_START_NET);

        info->in_src = ip.saddr;
        info->in_dst = ip.daddr;

        l4_protocol = ip.protocol;
        l4_offset = ip.ihl * 4;
    } else if (l3_protocol == ETH_P_IPV6) {
        info->is_ipv6 = 1;

        struct ipv6hdr ip6 = {};
        bpf_skb_load_bytes_relative(skb, 0, &ip6, sizeof(ip6),
                                    BPF_HDR_START_NET);

        info->in6_src = ip6.saddr;
        info->in6_dst = ip6.daddr;

        l4_protocol = ip6.nexthdr;
        l4_offset = sizeof(ip6);

        parse_ipv6_ext(skb, info, &l4_protocol, &l4_offset);
    }

    if (l4_protocol != 0) {
        if (l4_protocol == IPPROTO_TCP) {
            info->is_tcp = 1;

            struct tcphdr tcp = {};
            bpf_skb_load_bytes_relative(skb, l4_offset, &tcp, sizeof(tcp),
                                        BPF_HDR_START_NET);

            info->src_port = tcp.source;
            info->dst_port = tcp.dest;
        } else if (l4_protocol == IPPROTO_UDP) { /* TODO: add udplite? */
            info->is_udp = 1;

            struct udphdr udp = {};
            bpf_skb_load_bytes_relative(skb, l4_offset, &udp, sizeof(udp),
                                        BPF_HDR_START_NET);

            info->src_port = udp.source;
            info->dst_port = udp.dest;
        }
    }
}

static inline __u32 calculate_rss_hash(struct __sk_buff *skb,
        struct rss_config_t *config, struct toeplitz_key_data_t *toe)
{
    __u8 rss_input[HASH_CALCULATION_BUFFER_SIZE] = {};
    size_t bytes_written = 0;
    __u32 result = 0;
    struct packet_hash_info_t packet_info = {};

    parse_packet(skb, &packet_info);

    if (packet_info.is_ipv4) {
        if (packet_info.is_tcp &&
            config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_TCPv4) {

            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.in_src,
                                 sizeof(packet_info.in_src));
            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.in_dst,
                                 sizeof(packet_info.in_dst));
            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.src_port,
                                 sizeof(packet_info.src_port));
            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.dst_port,
                                 sizeof(packet_info.dst_port));
        } else if (packet_info.is_udp &&
                   config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_UDPv4) {

            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.in_src,
                                 sizeof(packet_info.in_src));
            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.in_dst,
                                 sizeof(packet_info.in_dst));
            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.src_port,
                                 sizeof(packet_info.src_port));
            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.dst_port,
                                 sizeof(packet_info.dst_port));
        } else if (config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_IPv4) {
            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.in_src,
                                 sizeof(packet_info.in_src));
            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.in_dst,
                                 sizeof(packet_info.in_dst));
        }
    } else if (packet_info.is_ipv6) {
        if (packet_info.is_tcp &&
            config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_TCPv6) {

            if (packet_info.is_ipv6_ext_src &&
                config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_TCP_EX) {

                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_ext_src,
                                     sizeof(packet_info.in6_ext_src));
            } else {
                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_src,
                                     sizeof(packet_info.in6_src));
            }
            if (packet_info.is_ipv6_ext_dst &&
                config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_TCP_EX) {

                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_ext_dst,
                                     sizeof(packet_info.in6_ext_dst));
            } else {
                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_dst,
                                     sizeof(packet_info.in6_dst));
            }
            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.src_port,
                                 sizeof(packet_info.src_port));
            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.dst_port,
                                 sizeof(packet_info.dst_port));
        } else if (packet_info.is_udp &&
                   config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_UDPv6) {

            if (packet_info.is_ipv6_ext_src &&
               config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_UDP_EX) {

                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_ext_src,
                                     sizeof(packet_info.in6_ext_src));
            } else {
                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_src,
                                     sizeof(packet_info.in6_src));
            }
            if (packet_info.is_ipv6_ext_dst &&
               config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_UDP_EX) {

                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_ext_dst,
                                     sizeof(packet_info.in6_ext_dst));
            } else {
                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_dst,
                                     sizeof(packet_info.in6_dst));
            }

            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.src_port,
                                 sizeof(packet_info.src_port));
            net_rx_rss_add_chunk(rss_input, &bytes_written,
                                 &packet_info.dst_port,
                                 sizeof(packet_info.dst_port));

        } else if (config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_IPv6) {
            if (packet_info.is_ipv6_ext_src &&
               config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_IP_EX) {

                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_ext_src,
                                     sizeof(packet_info.in6_ext_src));
            } else {
                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_src,
                                     sizeof(packet_info.in6_src));
            }
            if (packet_info.is_ipv6_ext_dst &&
                config->hash_types & VIRTIO_NET_RSS_HASH_TYPE_IP_EX) {

                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_ext_dst,
                                     sizeof(packet_info.in6_ext_dst));
            } else {
                net_rx_rss_add_chunk(rss_input, &bytes_written,
                                     &packet_info.in6_dst,
                                     sizeof(packet_info.in6_dst));
            }
        }
    }

    if (bytes_written) {
        net_toeplitz_add(&result, rss_input, bytes_written, toe);
    }

    return result;
}

SEC("tun_rss_steering")
int tun_rss_steering_prog(struct __sk_buff *skb)
{

    struct rss_config_t *config = 0;
    struct toeplitz_key_data_t *toe = 0;

    __u32 key = 0;
    __u32 hash = 0;

    config = bpf_map_lookup_elem(&tap_rss_map_configurations, &key);
    toe = bpf_map_lookup_elem(&tap_rss_map_toeplitz_key, &key);

    if (config && toe) {
        if (!config->redirect) {
            return config->default_queue;
        }

        hash = calculate_rss_hash(skb, config, toe);
        if (hash) {
            __u32 table_idx = hash % config->indirections_len;
            __u16 *queue = 0;

            queue = bpf_map_lookup_elem(&tap_rss_map_indirection_table,
                                        &table_idx);

            if (queue) {
                return *queue;
            }
        }

        return config->default_queue;
    }

    return -1;
}

char _license[] SEC("license") = "GPL";
