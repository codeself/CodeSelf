#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define UF_URL_NUM_MAX		1024
#define UF_URL_MAX_LEN		32

#define UF_URL_FILTER_MIN		0x0902
#define UF_ADD_URL_FILTER		UF_URL_FILTER_MIN 
#define UF_UPDATE_URL_FILTER	UF_URL_FILTER_MIN+0x01
#define UF_DELETE_URL_FILTER	UF_URL_FILTER_MIN+0x02
#define UF_URL_FILTER_MAX		UF_URL_FILTER_MIN+0x03

#define uint8 unsigned char

struct uf_url {
	unsigned char url[UF_URL_MAX_LEN];
};

struct uf_url_policy {
	char pname[UF_URL_MAX_LEN];
	uint8 action;	
	struct uf_url url[UF_URL_NUM_MAX];
};

int sockfd = 0;
struct uf_url_policy test_policy = {
	.pname = "mdm",
	.action = 0,
	.url = {
			"www.qq.com",
			"www.sina.com"
			}
};

struct uf_url_policy test_policy_update = {
	.pname = "mdm",
	.action = 0,
	.url = {
			"www.ifeng.com",
			"www.baidu.com",
			"login.taobao.com",
			}
};

struct uf_url_policy test_policy_delete;

int creat_sock()
{
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd == -1) {
		return -1;
	}
	
	return 0;
}

int add_policy()
{
	int ret = 0;

	if((ret = setsockopt(sockfd, IPPROTO_IP, UF_ADD_URL_FILTER, 
								&test_policy, sizeof(test_policy)) != 0 ))
		printf("Add policy failure!\r");

	return 0;
}

/* update 必须完整的传入重新设置的URL*/
int update_policy()
{
	int ret = 0;

	if((ret = setsockopt(sockfd, IPPROTO_IP, UF_ADD_URL_FILTER, 
								&test_policy_update, sizeof(test_policy_update)) != 0 ))
		printf("Update policy failure!\r");

	return 0;
}

/* 删除策略传一个空的策略结构到kernel */
int delete_policy()
{
	int ret = 0;

	if((ret = setsockopt(sockfd, IPPROTO_IP, UF_ADD_URL_FILTER, 
								&test_policy_delete, sizeof(test_policy_delete)) != 0 ))
		printf("Delete policy failure!\r");

	return 0;
}

int main (int argc, char *argv[])
{
	char *opt;
	
	if (argc < 2) {
		printf("Useage:\n");
		printf("\tAdd policy:\n \t\t./polciytest a\n");
		printf("\tUpdate policy:\n \t\t./polciytest u\n");
		printf("\tDelete policy:\n \t\t./polciytest d\n");
		return 1;
	}

	opt = argv[1];

	creat_sock();
	if (sockfd == -1) {
		printf("set policy Socket create failure!\n");
		return 1;
	}
	
	if (*opt == 'a')
		add_policy();

	if (*opt == 'u')
		update_policy();

	if (*opt == 'd')
		delete_policy();

	close(sockfd);

	return 0;
}
