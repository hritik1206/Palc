#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include "hiredis/hiredis.h"

void log_error(char* format, ...);
void log_warning(char* format, ...);
void log_info(char* format, ...);
void logger_reset_state(void);
int logger_set_log_file(const char* filename);
void logger_set_out_stdout();
int rtnl_receive(int fd, struct msghdr *msg, int flags)
{
	int len;
	do { 
		len = recvmsg(fd, msg, flags);
	} while (len < 0 && (errno == EINTR || errno == EAGAIN));
	if (len < 0) {
		log_error("Netlink receive failed");
		perror("Netlink receive failed");
		return -errno;
	}
	if (len == 0) { 
		log_error("EOF on netlink");
		perror("EOF on netlink");
		return -ENODATA;
	}
	return len;
}
static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
	struct iovec *iov = msg->msg_iov;
	char *buf;
	int len;
	iov->iov_base = NULL;
	iov->iov_len = 0;
	len = rtnl_receive(fd, msg, MSG_PEEK | MSG_TRUNC);
	if (len < 0) {
		return len;
	}
	buf = malloc(len);
	if (!buf) {
		log_error("malloc failed");
		perror("malloc failed");
		return -ENOMEM;
	}
	iov->iov_base = buf;
	iov->iov_len = len;
	len = rtnl_receive(fd, msg, 0);
	if (len < 0) {
		free(buf);
		return len;
	}
	*answer = buf;
	return len;
}
void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len) {
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max) {
			tb[rta->rta_type] = rta;
		}
		rta = RTA_NEXT(rta,len);
	}
}
static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb) {
	__u32 table = r->rtm_table;
	if (tb[RTA_TABLE]) {
		table = *(__u32 *)RTA_DATA(tb[RTA_TABLE]);
	}
	return table;
}
void print_route(struct nlmsghdr* nl_header_answer,const char* hostname,int port,char* ip)
{
    struct rtmsg* r = NLMSG_DATA(nl_header_answer);
    int len = nl_header_answer->nlmsg_len;
    struct rtattr* tb[RTA_MAX+1];
    char ipaddress[100];
    char gateway[100];
    int table;
    char buf[256];
    unsigned isunix = 0;
    redisContext *c = redisConnect(hostname,port);    
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    if (isunix) {
        c = redisConnectUnixWithTimeout(hostname, timeout);
    } else {
        c = redisConnectWithTimeout(hostname, port, timeout);
    }
    if (c == NULL || c->err) {
        if (c) {
            printf("Connection error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("Connection error: can't allocate redis context\n");
        }
        exit(1);
    }     
    redisReply *reply;  			/* Temporary reply pointer */
    reply = redisCommand(c,"PING");
    len -= NLMSG_LENGTH(sizeof(*r));
    if (len < 0) {
        perror("Wrong message length");
        return;
    }    
    parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
    table = rtm_get_table(r, tb);
    if (r->rtm_family != AF_INET && table != RT_TABLE_MAIN) {
        return;
    }
    if (tb[RTA_DST]) {
        strcpy (ipaddress, inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_DST]), buf, sizeof(buf)));
        printf("%s/%u ", ipaddress, r->rtm_dst_len);  
    } else if (r->rtm_dst_len) {
        printf("0/%u ", r->rtm_dst_len);
    } else {
        printf("default ");
        strcpy (ipaddress,"0.0.0.0");
    }
    if (tb[RTA_GATEWAY]) {
        printf("via %s", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_GATEWAY]), buf, sizeof(buf)));
        strcpy (gateway,inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_GATEWAY]), buf, sizeof(buf)));
    }
    else{
        strcpy (gateway,"0.0.0.0");
    }
    reply = redisCommand(c,"SET %s  %s",ipaddress,gateway);
        freeReplyObject(reply);	
	if (tb[RTA_OIF]) {
		char if_nam_buf[IF_NAMESIZE];
		int ifidx = *(_u32 *)RTA_DATA(tb[RTA_OIF]);
		printf(" dev %s", if_indextoname(ifidx, if_nam_buf));
	}
    if (tb[RTA_SRC]) {
        printf("src %s", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_SRC]), buf, sizeof(buf)));
    }
    printf("\n");
}
int open_netlink()	{
	struct sockaddr_nl saddr;
	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		log_error("Failed to open netlink socket");
		perror("Failed to open netlink socket");
		return -1;
	}
	memset(&saddr, 0, sizeof(saddr));
	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();
	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		log_error("Failed to bind to netlink socket");
		perror("Failed to bind to netlink socket");
		close(sock);
		return -1;
	}
	return sock;
}
int do_route_dump_requst(int sock)	{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} nl_request;
	nl_request.nlh.nlmsg_type = RTM_GETROUTE;
	nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nl_request.nlh.nlmsg_len = sizeof(nl_request);
	nl_request.nlh.nlmsg_seq = time(NULL);
	nl_request.rtm.rtm_family = AF_INET;
	return send(sock, &nl_request, sizeof(nl_request), 0);
}
int get_route_dump_response(int sock,const char* hostname,int port,char* ip)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char *buf;
	int dump_intr = 0;
	int status = rtnl_recvmsg(sock, &msg, &buf);
	struct nlmsghdr *h = (struct nlmsghdr *)buf;
	int msglen = status;
	log_info("Main routing table IPv4\n");
	printf("Main routing table IPv4\n");

	while (NLMSG_OK(h, msglen)) {
		if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
			fprintf(stderr, "Dump was interrupted\n");
			free(buf);
			return -1;
		}
		if (nladdr.nl_pid != 0) {
			continue;
		}
		if (h->nlmsg_type == NLMSG_ERROR) {
			log_error("netlink reported error");
			perror("netlink reported error");
			free(buf);
		}
		print_route(h,hostname,port,ip);
		h = NLMSG_NEXT(h, msglen);
	}
	free(buf);
	return status;
}
typedef struct {			/* Helper structure for ip address data and attributes */
	char family;
	char bitlen;
	unsigned char data[sizeof(struct in6_addr)];
} _inet_addr;
#define NLMSG_TAIL(nmsg) \
      ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
int rtattr_add(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen,const char* hostname,int port)	/* Add new data */
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr, "rtattr_add error: message exceeded bound of %d\n", maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen) {
		memcpy(RTA_DATA(rta), data, alen);
	}
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}
int do_route(int sock, int cmd, int flags, _inet_addr *dst, _inet_addr *gw, int def_gw, int if_idx,const char* hostname,int port)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[4096];
	} nl_request;	
	nl_request.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));		/* Initialize request structure */
	nl_request.n.nlmsg_flags = NLM_F_REQUEST | flags;
	nl_request.n.nlmsg_type = cmd;
	nl_request.r.rtm_family = dst->family;
	nl_request.r.rtm_table = RT_TABLE_MAIN;
	nl_request.r.rtm_scope = RT_SCOPE_NOWHERE;

	if (cmd != RTM_DELROUTE) {				/* Set additional flags if NOT deleting route */
		nl_request.r.rtm_protocol = RTPROT_BOOT;
		nl_request.r.rtm_type = RTN_UNICAST;
	}
	nl_request.r.rtm_family = dst->family;
	nl_request.r.rtm_dst_len = dst->bitlen;		
	if (nl_request.r.rtm_family == AF_INET6) {
		nl_request.r.rtm_scope = RT_SCOPE_UNIVERSE;
	} else {
		nl_request.r.rtm_scope = RT_SCOPE_LINK;
	}
	
	if (gw->bitlen != 0) {					/* Set gateway */+
		rtattr_add(&nl_request.n, sizeof(nl_request), RTA_GATEWAY, &gw->data, gw->bitlen / 8,hostname,port);
		nl_request.r.rtm_scope = 0;
		nl_request.r.rtm_family = gw->family;
	}	
	if (!def_gw) {							/* Don't set destination and interface in case of default gateways */	
		rtattr_add(&nl_request.n, sizeof(nl_request), RTA_DST, &dst->data, dst->bitlen / 8,hostname,port);	// Set Dest network //
		rtattr_add(&nl_request.n, sizeof(nl_request), RTA_OIF, &if_idx, sizeof(int),hostname,port);			// Set interface //
	}	
	return send(sock, &nl_request, sizeof(nl_request), 0);		// Send message to the netlink //
}
int read_addr(char *addr, _inet_addr *res)						// parser of the string IP address //
{
	if (strchr(addr, ':')) {
		res->family = AF_INET6;
		res->bitlen = 128;
	} else {
		res->family = AF_INET;
		res->bitlen = 32;
	}
	return inet_pton(res->family, addr, res->data);
}
#define NEXT_CMD_ARG() do { argv++; if (--argc <= 0) exit(-1); } while(0)
int main(int argc,char **argv) {
	logger_reset_state();
	log_warning("This message goes to syslog");
	logger_set_out_stdout();
	logger_set_log_file("log1.txt");
	int default_gw = 0;
	int if_idx = 0;
	_inet_addr to_addr = { 0 };
	_inet_addr gw_addr = { 0 };
	int nl_cmd;
	int nl_flags;
	char ip[1024];
	unsigned isunix = 0;
	const char *hostname =  "127.0.0.1";
    int port =  6379;	
    redisContext *c = redisConnect(hostname,port);    
    struct timeval timeout = { 1, 500000 }; 	// 1.5 seconds
    if (isunix) {
        c = redisConnectUnixWithTimeout(hostname, timeout);
    } else {
        c = redisConnectWithTimeout(hostname, port, timeout);
    }
    if (c == NULL || c->err) {
        if (c) {
            printf("Connection error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("Connection error: can't allocate redis context\n");
        }
        exit(1);
    }     
    redisReply *reply;  						// Temporary reply pointer //
    reply = redisCommand(c,"PING"); 
	while (argc > 0) {							// Passing Command Line Arguments 
		if (strcmp(*argv, "add") == 0) {
            nl_cmd = RTM_NEWROUTE;
            nl_flags = NLM_F_CREATE | NLM_F_EXCL;
			log_info("Adding a Ip address and route\n");
        } else if (strcmp(*argv, "del") == 0) {
            nl_cmd = RTM_DELROUTE;
            nl_flags = 0;
			log_info("deleting a Ip address and route\n");

        } else if (strcmp(*argv, "to") == 0) {
            NEXT_CMD_ARG(); 					// skip "to" and jump to the actual destination addr //			
            if (read_addr(*argv, &to_addr) != 1) {
                fprintf(stderr, "Failed to parse destination network %s\n", *argv);				
		 		exit(-1);
            }
			if(nl_flags==0) {
			strcpy (ip,*argv);
			}		
        } else if (strcmp(*argv, "dev") == 0) {
            NEXT_CMD_ARG(); /* skip "dev" */			
            if_idx = if_nametoindex(*argv);
        } else if (strcmp(*argv, "via") == 0) {
            NEXT_CMD_ARG(); /* skip "via"*/			         
            if (strcmp(*argv, "default") == 0) {
                default_gw = 1;
                NEXT_CMD_ARG();				
            }
            if (read_addr(*argv, &gw_addr) != 1) {
                fprintf(stderr, "Failed to parse gateway address %s\n", *argv);
				exit(-1);
            }
        }
        argc--; argv++;
    }
	int nl_sock = open_netlink();	
	if (do_route_dump_requst(nl_sock) < 0) {
		log_error("Failed to perfom request");
		perror("Failed to perfom request");
		close(nl_sock);
		return -1;
	}
	do_route(nl_sock, nl_cmd, nl_flags, &to_addr, &gw_addr, default_gw, if_idx,hostname,port);
	get_route_dump_response(nl_sock,hostname,port,ip);
	close (nl_sock);
	if(nl_flags==0)
	{
		reply = redisCommand(c,"DEL %s",ip);
        freeReplyObject(reply);
	}
    return 0;
}
     
