#define NL80211_BAND_LC	5

#define skb_ext_reset LINUX_BACKPORT(skb_get_dsfield)
static inline int skb_get_dsfield(struct sk_buff *skb)
{
	switch (skb_protocol(skb, true)) {
	case cpu_to_be16(ETH_P_IP):
		if (!pskb_network_may_pull(skb, sizeof(struct iphdr)))
			break;
		return ipv4_get_dsfield(ip_hdr(skb));

	case cpu_to_be16(ETH_P_IPV6):
		if (!pskb_network_may_pull(skb, sizeof(struct ipv6hdr)))
			break;
		return ipv6_get_dsfield(ipv6_hdr(skb));
	}

	return -1;
}
