/*
 * This is the 2016-09-02 write of URL filter, aiming for kernel 3.5.x.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define UF_URL_NUM_MAX		1024
#define UF_URL_MAX_LEN		32

#define UF_URL_POLICY_MAX_SIZE (1 << 17)
#define UF_URL_POLICY_MIN_SIZE (1 << 4)
#define GFP_ATOMIC_URL_POLICY  (__GFP_NOWARN | __GFP_NORETRY | __GFP_NOMEMALLOC) 

#define uint8 unsigned char

struct uf_url {
	unsigned char url[UF_URL_MAX_LEN];
};

struct uf_url_policy {
	char pname[UF_URL_MAX_LEN];
	uint8 action;	
	struct uf_url url[UF_URL_NUM_MAX];
};

struct uf_url_ts {
	struct list_head list;
	uint8 action;	
	unsigned char *url;
	uint8 url_len;
	struct ts_config *conf;
};




#define UF_TLS1_VERSION                    0x0301
#define UF_TLS1_1_VERSION                  0x0302
#define UF_TLS1_2_VERSION                  0x0303
#define UF_TLS_CONTENTTYPE_HANDSHAKE		0x16
#define UF_TLS_HANDSHAKE_CLIENT_HELLO		0x01
#define UF_TLS_EXTENSION_SERVER_NAME		0x0000
#define UF_TLS_SERVER_NAME_TYPE_HOST		0x00

#define UF_TLS_VERSION_CHECK(version, result) \
	do { \
		if (version != UF_TLS1_VERSION \
			&& version != UF_TLS1_1_VERSION \
			&& version != UF_TLS1_2_VERSION) \
			result = 1; \
	} while (0)

struct tls_tlv {
	unsigned int tag;
	unsigned int length;
	unsigned char *value;
};

struct tls_handshake_head {
	__u8 handshake_type;
	__u8 length[3];
	__be16 version;
};

/* see RFC 2246 */
struct tls_plain_text {
	__u8 content_type;
	__be16 protocol_version;
	__be16	length;
	unsigned char *fragment;	
};
