/*
 * This is the 2016-09-02 write of URL filter, aiming for kernel 3.5.x.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/ip.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include <linux/string.h>
#include <linux/textsearch.h>

#include <linux/spinlock.h>
#include <linux/rculist.h>

#include "uf_url_filter.h"
#include "uf_send_skb.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jchenvi@hotmail.com");
MODULE_DESCRIPTION("uf url filter");

#define UF_URL_FILTER_ERROR 1
#define UF_TRUE	0
#define UF_FALSE	1

static DEFINE_SPINLOCK(spin_urlfilter_policy);
static DEFINE_SPINLOCK(spin_urlfilter_crlf);

struct uf_url_policy *url_policy = NULL;
static LIST_HEAD(url_policy_ts_head);
struct ts_config *conf_cr_lf = NULL;

static struct uf_url_ts *uf_url_policy_ts_alloc(void)
{
	struct uf_url_ts *url_policy_ts_new = NULL;

	url_policy_ts_new = kmalloc(sizeof(struct uf_url_ts), GFP_ATOMIC_URL_POLICY);
	if (url_policy_ts_new == NULL) {
		pr_err("%s <%d>: Firewall: urlfilter kmalloc policy_ts error!\n", 
										__func__, __LINE__);
		return NULL;
	}
		
	INIT_LIST_HEAD(&url_policy_ts_new->list);
	url_policy_ts_new->action = 0;
	url_policy_ts_new->url = NULL;
	url_policy_ts_new->url_len = 0;
	url_policy_ts_new->conf = NULL;

	return url_policy_ts_new;
}

static void uf_url_policy_ts_clean(void)
{
	struct list_head *p, *n;
	struct uf_url_ts *url_policy_ts_temp = NULL;

	spin_lock(&spin_urlfilter_policy);
	list_for_each_safe(p, n, &url_policy_ts_head) {
		url_policy_ts_temp = list_entry(p, struct uf_url_ts, list);

		url_policy_ts_temp->action = 0;

		if (url_policy_ts_temp->url)
			kfree(url_policy_ts_temp->url);
		url_policy_ts_temp->url_len = 0;

		if (url_policy_ts_temp->conf)
			textsearch_destroy(url_policy_ts_temp->conf);

		list_del_rcu(p);
		kfree(url_policy_ts_temp);
	}
	spin_unlock(&spin_urlfilter_policy);
}

static void uf_url_policy_ts_add(struct uf_url_ts *url_policy_ts_new)
{
	spin_lock(&spin_urlfilter_policy);
	list_add_tail_rcu(&url_policy_ts_new->list, &url_policy_ts_head);
	spin_unlock(&spin_urlfilter_policy);
}

static void uf_url_policy_ts_fini(void)
{
	uf_url_policy_ts_clean();
}

static int uf_url_filter_cr_lf_ts_init(void)
{
	int ret = 0;

	conf_cr_lf = textsearch_prepare("bm", "\r\n", 2, 
					GFP_KERNEL, TS_IGNORECASE|TS_AUTOLOAD);

	if (IS_ERR(conf_cr_lf))
		ret = UF_URL_FILTER_ERROR;

	return ret;
}

static void uf_url_filter_cr_lf_ts_fini(void)
{
	spin_lock(&spin_urlfilter_crlf);
	if (conf_cr_lf)
		textsearch_destroy(conf_cr_lf);
	spin_unlock(&spin_urlfilter_crlf);
}

static int uf_url_policy_to_ts(void)
{
	int i = 0, ret = 0;
	char *url_temp = NULL;
	int url_len = 0;
	struct uf_url_ts *url_policy_ts_new = NULL;

	 /*先清空ts config*/
	uf_url_policy_ts_clean();

	for (i = 0; i < UF_URL_NUM_MAX; i++) {
		url_len = strlen(url_policy->url[i].url);
		if (url_len == 0)
			continue;
	
		url_policy_ts_new = uf_url_policy_ts_alloc();
		if (url_policy_ts_new == NULL) {
			ret = UF_URL_FILTER_ERROR;
			uf_url_policy_ts_clean();
			break;
		}

		url_policy_ts_new->conf = textsearch_prepare("bm", url_policy->url[i].url, url_len, 
												GFP_KERNEL, TS_IGNORECASE|TS_AUTOLOAD);
		if (IS_ERR(url_policy_ts_new->conf)) {
			ret = UF_URL_FILTER_ERROR;
			/* 构造ts config 过程中如果出错，把已构造的清空。*/
			uf_url_policy_ts_clean();
			break;
		} else {
			url_temp = kmalloc(url_len+1, GFP_ATOMIC_URL_POLICY);
			if (url_temp == NULL) {
				ret = UF_URL_FILTER_ERROR;
				uf_url_policy_ts_clean();
				break;
			}
			url_policy_ts_new->url = url_temp;
			url_policy_ts_new->url[url_len] = '\0';
			/*如果url长度超过32个字节，截断32字节*/
			memcpy(url_policy_ts_new->url, url_policy->url[i].url, 
						(url_len <= UF_URL_MAX_LEN ? url_len : UF_URL_MAX_LEN));
			url_policy_ts_new->url_len = strlen(url_policy_ts_new->url);
		}

		printk("url_policy_ts_new->url = %s, url_policy_ts_new->url len = %d\n", 
					url_policy_ts_new->url, (int)strlen(url_policy_ts_new->url));

		uf_url_policy_ts_add(url_policy_ts_new);
	}	

	return ret;	
}

static int uf_url_add_policy(void __user *user, unsigned long len)
{
	void *vm_policy = NULL;
	int ret = 0;

	if (len > UF_URL_POLICY_MAX_SIZE) {
		pr_err("%s <%d>: Firewall: urlfilter policy size maxsize 128KB error!\n", 
										__func__, __LINE__);
		ret = UF_URL_FILTER_ERROR;
		goto add_policy_err;
	}	

	vm_policy = kmalloc(len, GFP_ATOMIC_URL_POLICY);
	if (vm_policy == NULL) {
		pr_err("%s <%d>: Firewall: urlfilter policy kmalloc error!\n", 
										__func__, __LINE__);
		ret = UF_URL_FILTER_ERROR;
		goto add_policy_err;	
	}
	
	url_policy = (struct uf_url_policy *)vm_policy;
	if (copy_from_user(url_policy, user, len) != 0) {
		pr_err("%s <%d>: Firewall: urlfilter policy copy_from_user error!\n", 
										__func__, __LINE__);
		ret = UF_URL_FILTER_ERROR;
		goto cleanup_policy;
	}
	
	if (uf_url_policy_to_ts()) {
		pr_err("%s <%d>: Firewall: urlfilter policy converted into ts error!\n", 
										__func__, __LINE__);
		ret = UF_URL_FILTER_ERROR;
	}

cleanup_policy:
	kfree(url_policy);
add_policy_err:

	return ret;
}

static int uf_url_update_policy(void __user *user, unsigned long len)
{
	int ret = 0;
	
	ret = uf_url_add_policy(user, len);

	return ret;
}

static int uf_url_delete_policy(void __user *user, unsigned long len)
{
	int ret = 0;

	/*只需要把ts config释放掉*/
	uf_url_policy_ts_fini();

	return ret;
}

#define UF_URL_FILTER_MIN		0x0902
#define UF_ADD_URL_FILTER		UF_URL_FILTER_MIN 
#define UF_UPDATE_URL_FILTER	UF_URL_FILTER_MIN+0x01
#define UF_DELETE_URL_FILTER	UF_URL_FILTER_MIN+0x02
#define UF_URL_FILTER_MAX		UF_URL_FILTER_MIN+0x03

static int uf_set_urlfilter_policy(struct sock *sk, int optval, 
					void __user *user, unsigned int len)
{
	int ret = 0;

	switch (optval) {
	case UF_ADD_URL_FILTER:
		ret = uf_url_add_policy(user, len);
		break;
	case UF_UPDATE_URL_FILTER:
		ret = uf_url_update_policy(user, len);
		break;
	case UF_DELETE_URL_FILTER:
		ret = uf_url_delete_policy(user, len);
		break;
	default:
		break;
	}
	
	return ret;
}

static struct nf_sockopt_ops uf_urlfiler_policy = {
	.pf		= PF_INET,
	.set_optmin	= UF_URL_FILTER_MIN,
	.set_optmax	= UF_URL_FILTER_MAX,
	.set		= uf_set_urlfilter_policy,
	.owner		= THIS_MODULE,
};

/* host 检查 */
static int uf_host_check(char *host, int host_len)
{
	int ret = UF_FALSE;
	int pos = -1;
	struct ts_state state;
	struct uf_url_ts *url_policy_ts_temp = NULL;

	list_for_each_entry_rcu(url_policy_ts_temp, &url_policy_ts_head, list) {
		pos = textsearch_find_continuous(url_policy_ts_temp->conf, &state, host, host_len);
		if (pos >= 0) {
			ret = UF_TRUE;
			break;
		}
	}

	return ret;
}

 /* 在调本函数之前要确保是tcp, 本函数不做是否tcp的检查 
  * 获取tcp的 payload 数据,因为是host过滤，所以本模块只处理tcp
 */
static void uf_get_l7_payload(struct sk_buff *skb, char **payload, int *payload_len)
{
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph = NULL;
	struct tcphdr _tcph;
	u_int8_t nexthdr;
	__be16 frag_off;
	unsigned int l3_header_len = 0, tcphoff = 0;
	unsigned int l4offset = 0, l7offset = 0;
	
	if (skb_is_nonlinear(skb))
		return;
	
	/* 数据长度不超过l3和l4头部长度的最小和(20+20), 没有L7层数据 */	
	if (skb->len <= 40)
		return;

	if (ntohs(skb->protocol) == ETH_P_IP) {
		iph = ip_hdr(skb);
		l3_header_len = iph->ihl << 2;
	} else if (ntohs(skb->protocol) == ETH_P_IPV6) {
		ip6h = ipv6_hdr(skb);
		nexthdr = ip6h->nexthdr;
		tcphoff = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &nexthdr, &frag_off);
		if (tcphoff < 0 || tcphoff > skb->len)
			return;
		l3_header_len = tcphoff - skb_network_offset(skb);	
	} else {
		return;
	}

	l4offset = l3_header_len + skb_network_offset(skb);
	if (skb->len < l4offset)
		return;

	tcph = skb_header_pointer(skb, l4offset, sizeof(_tcph), &_tcph);
	if (tcph == NULL)
		return;
	
	l7offset = l4offset + (tcph->doff << 2);
	if (skb->len < l7offset)
		return;
	
	*payload = (unsigned char *)tcph + (tcph->doff << 2);
	*payload_len = skb->len - l7offset;	
}

/*查找回车换行符号*/
static char* uf_http_find_cr_lf(char *payload, int payload_len)
{
	int pos = -1;
	char *cr_lf = NULL;
	struct ts_state state;

	spin_lock(&spin_urlfilter_crlf);
	pos = textsearch_find_continuous(conf_cr_lf, &state, payload, payload_len);
	spin_unlock(&spin_urlfilter_crlf);
	if (pos >= 0)
		cr_lf = payload + pos;

	return cr_lf;
}

static int uf_http_filter(char *payload, int payload_len)
{
	int ret = NF_DROP;
	/* payload 中第一个\r\n*/
	char *cr_lf = NULL;
	char *second_cr_lf = NULL;
	char *host = NULL;
	int host_len = 0;
	int pre_len = 0, next_len = 0;
	
	cr_lf = uf_http_find_cr_lf(payload, payload_len);
	if (cr_lf == NULL)
		return NF_ACCEPT;

	pre_len = cr_lf - payload;
	next_len = payload_len - pre_len;
	
	/* http前两个\r\n处的文本格式为 HTTP/1.x\r\nHost: www.host.com\r\n
	 * 以下两种情况不认为是HTTP报文
	 * 1、如果第一个\r\n和paylaod之间的空间不够放下HTTP/1.x，
	 * 2、如果第一个\r\n到报文结束之间的空间不够放下\r\nHost: (":"后面有空格) 
	*/
	if (pre_len < 8 || next_len < 8)
		return NF_ACCEPT;

	if (*(cr_lf-8) != 'H'
		|| *(cr_lf-7) != 'T'
		|| *(cr_lf-6) != 'T'
		|| *(cr_lf-5) != 'P'
		|| *(cr_lf+2) != 'H'
		|| *(cr_lf+3) != 'o'
		|| *(cr_lf+4) != 's'
		|| *(cr_lf+5) != 't'
		|| *(cr_lf+6) != ':')
		return NF_ACCEPT;

	/* 找第二个\r\n，计算host的长度
	 * 暂时不支持分片时，可能出现的host在两个skb的问题，
	 * 如果需要支持，需要做ct扩展和处理乱序问题
	*/
	host = cr_lf+8;
	second_cr_lf = uf_http_find_cr_lf(host, (next_len - 8));
	if (second_cr_lf == NULL)
		return NF_ACCEPT;
	
	host_len = second_cr_lf - host;

	if (uf_host_check(host, host_len))
		return NF_ACCEPT;
	
	return ret;
}

static int uf_https_parse_tls_plain_text(struct tls_plain_text *plain_text,
								 				char *payload, int payload_len)
{
	/* 传入的数据长度不够 sizeof(struct tls_plain_text) */
	if (payload_len < 5)
		return UF_FALSE;
	
	plain_text->content_type = *payload;
	memcpy(&plain_text->protocol_version, 
			payload+sizeof(plain_text->content_type), 
			sizeof(plain_text->protocol_version));
	memcpy(&plain_text->length, 
			payload+sizeof(plain_text->content_type)+sizeof(plain_text->protocol_version),
			sizeof(plain_text->length));
	plain_text->fragment = payload + 5;

	plain_text->protocol_version = ntohs(plain_text->protocol_version);
	plain_text->length = ntohs(plain_text->length);

	if (plain_text->length != (payload_len - 5))
		return UF_FALSE;
	
	return UF_TRUE;
}

static int uf_https_parse_tls_handshake_head(struct tls_handshake_head *handshake_head,
													char *payload, int payload_len)
{
	__u8 notohs_bak = 0;
	
	/* 传入的数据长度不够 sizeof(struct tls_handshake_head) */
	if (payload_len < 6)
		return UF_FALSE;

	memcpy(handshake_head, payload, 6);
	
	/* handshake length noths, 三字节的，只需调换[0]和[2]即可 */	
	notohs_bak = handshake_head->length[0];
	handshake_head->length[0] = handshake_head->length[2];
	handshake_head->length[2] = notohs_bak;

	handshake_head->version = ntohs(handshake_head->version);

	return UF_TRUE;
}

static int uf_https_handshake_skip_to_extension(unsigned char **extension,
														unsigned int *extension_size, 
														char *payload, int payload_len)
{
	unsigned int const_len = 0;
	unsigned int session_id_len = 0;
	unsigned int suites_length = 0;
	unsigned char *cipher_suites_length = NULL;
	unsigned int methods_length = 0;
	unsigned char *compression_methods_length = NULL;
	unsigned char *extension_length = NULL;
	unsigned int len1 = 0, len2 = 0, len3 = 0;

#define RANDOM_SIZE 32
#define SESSION_ID_SIZE	1
#define CIPHER_SUITES_LENGTH_SIZE	2
#define COMPRESSION_METHODS_LENGTH_SIZE	1
#define EXTENSIONS_LENGTH_SIZE	2

	const_len = RANDOM_SIZE + SESSION_ID_SIZE;	
	if (payload_len < const_len)
		return UF_FALSE; 

	session_id_len = *(payload + RANDOM_SIZE);
	len1 = const_len + session_id_len;
	if (payload_len < len1 + CIPHER_SUITES_LENGTH_SIZE)
		return UF_FALSE;

	cipher_suites_length = payload + len1;
	memcpy(&suites_length, cipher_suites_length, CIPHER_SUITES_LENGTH_SIZE);
	suites_length = ntohs(suites_length);

	len2 = len1 + CIPHER_SUITES_LENGTH_SIZE + suites_length;
	if (payload_len < len2 + COMPRESSION_METHODS_LENGTH_SIZE)
		return UF_FALSE;
	compression_methods_length = payload + len2;

	methods_length = *compression_methods_length;
	len3 = len2 + COMPRESSION_METHODS_LENGTH_SIZE + methods_length;
	if (payload_len < len3 + EXTENSIONS_LENGTH_SIZE)
		return UF_FALSE;

	extension_length = payload + len3;	
	memcpy(extension_size, extension_length, EXTENSIONS_LENGTH_SIZE);
	*extension_size = ntohs(*extension_size);
	if (payload_len < len3 + EXTENSIONS_LENGTH_SIZE + *extension_size)
		return UF_FALSE;

	*extension = extension_length + EXTENSIONS_LENGTH_SIZE;

	return UF_TRUE;	
}

static int uf_https_get_host_from_extension(unsigned char *extension, 
													unsigned int extension_size,
													unsigned char **host,
													unsigned int *host_len)
{
	int ret = UF_FALSE;
	unsigned int type = 0;
	unsigned int len = 0;
	unsigned int server_name_len = 0;
	unsigned int pass_len = 0;
	unsigned int const_len = 0;
	unsigned char * extension_temp = NULL;

#define EXTENSION_HOST_TYPE	0x0000
#define EXTENSION_TYPE_SIZE 2
#define EXTENSION_VALUE_SIZE 2

#define EXTENSION_HOST_HEAD_SIZE 4
#define EXTENSION_HOST_VALUE_HEAD 5

#define SERVER_NAME_TYPE_HOST 0x00
#define SERVER_NAME_TYPE_OFFSET 6
#define SERVER_NAME_LENGTH_OFFSET 7

	if (extension == NULL || extension_size == 0)
		return UF_FALSE;

	const_len = EXTENSION_TYPE_SIZE + EXTENSION_VALUE_SIZE;
	extension_temp = extension;
	do {
		memcpy(&type, extension_temp, EXTENSION_TYPE_SIZE);
		type = ntohs(type);
		memcpy(&len, extension_temp + EXTENSION_TYPE_SIZE, EXTENSION_VALUE_SIZE);
		len = ntohs(len);
		pass_len += const_len + len;
		if (pass_len > extension_size)
			break;

		/* 检查extension类型是否是 server_name 0x0000*/
		if (type != EXTENSION_HOST_TYPE) {
			extension_temp += pass_len;
			continue;
		}

		if (len < SERVER_NAME_LENGTH_OFFSET + 2) {
			ret = UF_FALSE;
			break;
		}

		/* 检查 Server Name Type 是否为0x00*/
		if (*(extension_temp + SERVER_NAME_TYPE_OFFSET)
				!= SERVER_NAME_TYPE_HOST) {
			ret = UF_FALSE;
			break;
		}

		memcpy(&server_name_len, extension_temp + SERVER_NAME_LENGTH_OFFSET, 2);
		server_name_len = ntohs(server_name_len);

		/* 如果extension tlv value的长度减去server name indication extension头部定长的５个字节
			不等于server name indicatino extension中标记的host长度 */
		if ((len - 5) != server_name_len) {
			ret = UF_FALSE;
			break;
		}

		if (extension_size <= pass_len + SERVER_NAME_LENGTH_OFFSET + 2 + server_name_len) {
			ret = UF_FALSE;
			break;
		}

		*host = extension_temp + EXTENSION_HOST_HEAD_SIZE + EXTENSION_HOST_VALUE_HEAD;
		*host_len = server_name_len;
		ret = UF_TRUE;
	} while (pass_len < extension_size && *host == NULL);
	
	return ret;
}

/* 只处理TLS握手的 client hello包 */
static int uf_https_filter(char *payload, int payload_len)
{
	char result = 0;
	int handshake_data_len = 0;
	int handshake_head_len = 0;
	int handshake_payload_len = 0;
	__be16 tls_version = 0;
	struct tls_plain_text plain_text;
	struct tls_handshake_head handshake_head;
	unsigned char *extension = NULL;
	unsigned int extension_size = 0;
	unsigned char *handshake_payload = NULL;
	unsigned char *host = NULL;
	unsigned int host_len = 0;

	memset(&plain_text, 0, sizeof(struct tls_plain_text));
	memset(&handshake_head, 0, sizeof(struct tls_handshake_head));
	
	/* 解析 TLSPlaintext，确定是否NF_ACCEPT */
	if (uf_https_parse_tls_plain_text(&plain_text, payload, payload_len))
		return NF_ACCEPT;
	
	if (plain_text.content_type != UF_TLS_CONTENTTYPE_HANDSHAKE)
		return NF_ACCEPT;

	tls_version = plain_text.protocol_version;
	UF_TLS_VERSION_CHECK(tls_version, result);		
	if (result)
		return NF_ACCEPT;
	
	if (*(plain_text.fragment) != UF_TLS_HANDSHAKE_CLIENT_HELLO)
		return NF_ACCEPT;

	/* 解析handshake head, 确定是否NF_ACCEPT */
	if (uf_https_parse_tls_handshake_head(&handshake_head, 
											plain_text.fragment,
											plain_text.length))
		return NF_ACCEPT;

	/*
	 * 检查数据长度的合法性 
	 * 3 是handshake_head->length的字节数
	 * 4 是handshake_type和length字节总数 
	*/
	memcpy(&handshake_data_len, handshake_head.length, 3);
	if ((handshake_data_len + 4) != plain_text.length)
		return NF_ACCEPT;

	UF_TLS_VERSION_CHECK(handshake_head.version, result);
	if (result)
		return NF_ACCEPT;
	
	handshake_head_len = sizeof(struct tls_handshake_head);
	handshake_payload = plain_text.fragment+handshake_head_len;
	handshake_payload_len = plain_text.length - handshake_head_len;

	/* 获取tls包中extension */
	if (uf_https_handshake_skip_to_extension(&extension, &extension_size,
												handshake_payload, handshake_payload_len))
		return NF_ACCEPT;

	/* 从extension中查找host */
	if (uf_https_get_host_from_extension(extension, extension_size, &host, &host_len))
		return NF_ACCEPT;
	
	if (uf_host_check(host, host_len))
		return NF_ACCEPT;

	return NF_DROP;
}

static unsigned int uf_urlfilter(char *payload, int payload_len)
{
	if (uf_http_filter(payload, payload_len) == NF_DROP)
		return NF_DROP;

	if (uf_https_filter(payload, payload_len) == NF_DROP)
		return NF_DROP;

	return NF_ACCEPT;
}

static unsigned int uf_urlfilter_ipv4_hook(unsigned int hooknum,
					struct sk_buff *skb,
					const struct net_device *in,
					const struct net_device *out,
					int (*okfn)(struct sk_buff *))
{
	int payload_len = 0;
	char *payload = NULL;
	int ret = NF_ACCEPT;

	if ((ip_hdr(skb)->protocol) != IPPROTO_TCP)
		return NF_ACCEPT;
	
	uf_get_l7_payload(skb, &payload, &payload_len);
	if (payload == NULL || payload_len <= 0)
		return NF_ACCEPT;

	ret = uf_urlfilter(payload, payload_len);

	if (ret == NF_DROP) {
		uf_send_resetskb_to_sender(skb, hooknum);
		uf_send_resetskb_to_receiver(skb, hooknum);
	}

	return ret;
}

static unsigned int uf_urlfilter_ipv6_hook(unsigned int hooknum,
					struct sk_buff *skb,
					const struct net_device *in,
					const struct net_device *out,
					int (*okfn)(struct sk_buff *))
{
	int payload_len = 0;
	char *payload = NULL;
	int ret = NF_ACCEPT;

	if (ntohs(ipv6_hdr(skb)->nexthdr) != IPPROTO_TCP)
		return NF_ACCEPT;

	uf_get_l7_payload(skb, &payload, &payload_len);
	if (payload == NULL || payload_len <= 0)
		return NF_ACCEPT;

	ret = uf_urlfilter(payload, payload_len);
	if (ret == NF_DROP) {
		uf_send_resetskb_to_sender(skb, hooknum);
		uf_send_resetskb_to_receiver(skb, hooknum);
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops uf_urlfilter_hook_ops[] __read_mostly =
{
	{
		.hook = uf_urlfilter_ipv4_hook,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_LAST-1, 
	},
	{
		.hook = uf_urlfilter_ipv4_hook,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST-1, 
	},

	{
		.hook = uf_urlfilter_ipv6_hook,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP6_PRI_LAST-1, 
	},
	{
		.hook = uf_urlfilter_ipv6_hook,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP6_PRI_LAST-1, 
	},
};

static int __init uf_urlfilter_init(void)
{
	int ret = 0;

	ret = uf_url_filter_cr_lf_ts_init();
	if (ret)
		return ret;

	ret = nf_register_sockopt(&uf_urlfiler_policy);
	if (ret < 0) {
		pr_err("Firewall: can't register urlfilter socket option!\n");
		goto cleanup_crlf_ts;
	}
	
	ret = nf_register_hooks(uf_urlfilter_hook_ops,
				ARRAY_SIZE(uf_urlfilter_hook_ops));
	if (ret < 0) {
		pr_err("Firewall: can't register urlfilter hooks!\n");
		goto cleanup_sockopt;
	}

	return ret;	

cleanup_sockopt:
	nf_unregister_sockopt(&uf_urlfiler_policy);
cleanup_crlf_ts:
	uf_url_filter_cr_lf_ts_fini();

	return ret;
}

static void __exit uf_urlfilter_fini(void)
{
	uf_url_policy_ts_fini();
	uf_url_filter_cr_lf_ts_fini();
	nf_unregister_hooks(uf_urlfilter_hook_ops, 
			ARRAY_SIZE(uf_urlfilter_hook_ops));
	nf_unregister_sockopt(&uf_urlfiler_policy);
}

module_init(uf_urlfilter_init);
module_exit(uf_urlfilter_fini);
