//
// Created by dave on 18-8-15.
//

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>

#define ICMP_TIMEOUT    2000
#define MAX_IP_LEN      60
#define MAX_BUF_SIZE  1024
#define MAX_ICMP_LEN  76
#define DEF_DATA_LEN    (64 - ICMP_MINLEN)
#define MAX_PACKET_LEN  (65536 - 60 - ICMP_MINLEN)

using namespace std;

uint16_t in_cksum(uint16_t *addr, unsigned len);
int ping(const string &target);


int main(int argc, char *argv[]){

    if (argc != 2){
        printf("Usage: %s example.com\n", argv[0]);
        exit(0);
    }

    string target = argv[1];
    ping(target);
}

int send_icmp_pkt(sockaddr_in &remote_addr, int sock_fd, int ttl){
    icmp *icmp_pkt = new icmp;
    icmp_pkt->icmp_type = ICMP_ECHO;
    icmp_pkt->icmp_code = 0;
    icmp_pkt->icmp_seq = static_cast<u_int16_t>(ttl);
    icmp_pkt->icmp_id = static_cast<u_int16_t>(getpid());

    int pkt_size = DEF_DATA_LEN + ICMP_MINLEN;
    icmp_pkt->icmp_cksum = 0;
    icmp_pkt->icmp_cksum = in_cksum((unsigned short *)icmp_pkt, static_cast<unsigned int>(pkt_size));

    auto ret = sendto(sock_fd, (char *)icmp_pkt, pkt_size, 0, (struct sockaddr*)&remote_addr, (socklen_t)sizeof(remote_addr));

    return static_cast<int>(ret);
}

int ping(const string &target)
{

    int i, ret, sock, seq_id = 1;
    int recv_len, ip_header_len;
    int icmp_size, pkt_size;
    char host_buff[MAX_BUF_SIZE];
    float elapsed;
    string host_name, host_ip;

    struct ip *ip_header;
    struct icmp *icp;
    struct hostent *host;
    struct sockaddr_in to{}, from{};
    struct timeval start{}, end{}, tv{};

    u_char *packet, outpack[MAX_PACKET_LEN];

    to.sin_family = AF_INET;

    to.sin_addr.s_addr = inet_addr(target.c_str());
    if (to.sin_addr.s_addr != (u_int)-1){
        host_ip = target;
        host_name = target;
    } else {
        host = gethostbyname(target.c_str());
        if (!host)
        {
            cerr << "unknown host "<< target << endl;
            return -1;
        }
        to.sin_family = static_cast<sa_family_t>(host->h_addrtype);
        bcopy(host->h_addr, (caddr_t)&to.sin_addr, host->h_length);
        strncpy(host_buff, host->h_name, sizeof(host_buff) - 1);
        host_ip = inet_ntoa(*(struct in_addr*)host->h_addr_list[0]);
        host_name = host_buff;
    }

    pkt_size = DEF_DATA_LEN + MAX_IP_LEN + MAX_ICMP_LEN;
    packet = (u_char *)malloc((u_int)pkt_size);

    if (!packet) {
        cerr << "packet malloc error." << endl;
        return -1;
    }

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        cerr << "Please run as superuser." << endl;
        return -1; /* Needs to run as superuser!! */
    }

    printf("PING %s (%s) with %d(%d) bytes of data:\n", host_name.c_str(), host_ip.c_str(), DEF_DATA_LEN, pkt_size);

    send_icmp_pkt(to, sock, seq_id);
    ip_header_len = sizeof(struct ip);

    struct timeval timeout={2,0};//2s
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
//    setsockopt(sock, SOL_SOCKET, IP_TTL, &timeout, sizeof(timeout));

    while(true)
    {
        gettimeofday(&start, nullptr);

        recv_len = sizeof(sockaddr_in);
        ret = recvfrom(sock, (char *)packet, pkt_size, 0,(struct sockaddr *)&from, (socklen_t*)&recv_len);

        if(ret == -1 && errno == EAGAIN){
            // timeout
            printf("timeout.\n");
            seq_id += 1;

            gettimeofday(&start, nullptr);
            send_icmp_pkt(to, sock, seq_id);

            continue;

        }else if(ret < 0){
            // perror("recvfrom error: %i \n", errno);
            printf("recvfrom error: %i \n", errno);
            return -1;
        }

        // Check the IP header
        ip_header = (struct ip *)((char*)packet);
        if (ret < (ip_header_len + ICMP_MINLEN)) {
            cerr << "packet too short (" << ret  << " bytes) from " << host_name << endl;;
            return -1;
        }

        // Now the ICMP part
        icp = (struct icmp *)(packet + ip_header_len);
        if (icp->icmp_type != ICMP_ECHOREPLY)
            continue;

        if (icp->icmp_id != getpid()) {
            // not send by this process
            //cout << "received id " << icp->icmp_id << endl;
            continue;
        }

        if (icp->icmp_seq != seq_id) {
            // wrong icmp seq, may be resend
            //cout << "received sequence # " << icp->icmp_seq << endl;
            continue;
        }

        gettimeofday(&end, nullptr);

        elapsed = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        elapsed = elapsed / 1000;

        printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n",
               ret - ip_header_len, host_ip.c_str(), icp->icmp_seq, ip_header->ip_ttl, elapsed);

        sleep(1);
        seq_id += 1;

        gettimeofday(&start, nullptr);
        send_icmp_pkt(to, sock, seq_id);
    }

    return 0;
}

uint16_t in_cksum(uint16_t *addr, unsigned len)
{
    uint16_t answer = 0;
    /*
     * Algorithm is simple, using a 32 bit aicmp_sizeumulator (sum), add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the t   16 bits into the lower 16 bits.
     */
    uint32_t sum = 0;
    while (len > 1)  {
        sum += *addr++;
        len -= 2;
    }

    if (len == 1) {
        *(unsigned char *)&answer = *(unsigned char *)addr ;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}
