//
// Created by dave on 18-8-15.
//

#include "trace.h"

#define DEF_MAX_HOP     30
#define MAX_IP_LEN      60
#define MAX_BUF_SIZE	1024
#define MAX_ICMP_SIZE	1024
#define MAX_ICMP_LEN	76
#define DEF_DATA_LEN    (64 - ICMP_MINLEN)
#define ICMP_HEADER_LEN 8

using namespace std;

uint16_t in_cksum(uint16_t *addr, unsigned len);
int trace(const string &target);


int main(int argc, char *argv[]){

   if (argc != 2){
       printf("Usage: %s example.com\n", argv[0]);
       exit(0);
   }

   string target = argv[1];
   trace(target);
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

   setsockopt(sock_fd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
   auto ret = sendto(sock_fd, (char *)icmp_pkt, pkt_size, 0, (struct sockaddr*)&remote_addr, (socklen_t)sizeof(remote_addr));

   return static_cast<int>(ret);
}

int trace(const string &target)
{

   int i, ret, ready, sock;
   int recv_len, ip_header_len, pkt_size;
   int ttl = 1;
   char host_buff[MAX_BUF_SIZE];
   bool reach_dest = false;
   u_char *packet;
   string host_name, host_ip, src_ip;

   struct ip *ip_header;
   struct ip *ip_header_inner;
   struct icmp *icp;
   struct icmp *icp_inner;
   struct hostent *host;
   struct sockaddr_in to{}, from{};
   struct timeval start{}, end{}, tv{};

   to.sin_family = AF_INET;
   to.sin_addr.s_addr = inet_addr(target.c_str());

   if (to.sin_addr.s_addr != (u_int)-1){
       host_ip = target;
       host_name = target;
       cout << "Tracing route to " << host_ip
            << " with a maximum of " << DEF_MAX_HOP << " hops." << endl;
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
       cout << "Tracing route to " << host_name
            << " [" << host_ip << "]"
            << " with a maximum of " << DEF_MAX_HOP << " hops." << endl;
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
       return -1;
   }

   ip_header_len = sizeof(struct ip);

   struct timeval timeout={2,0};//2s
   setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
   setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

   while(!reach_dest && ttl <= DEF_MAX_HOP){

       timeval timers[3];
       for(i = 0 ; i < 3 ; ++i)
       {
           timeval tmp_timer{};
           send_icmp_pkt(to, sock, ttl);
           gettimeofday(&tmp_timer, nullptr);
           timers[i] = tmp_timer;
       }

       i = 0;
       printf("%d", ttl);

       while (true) {

           fd_set descriptors;

           FD_ZERO(&descriptors);
           FD_SET(sock, &descriptors);

           tv.tv_sec = 1;
           tv.tv_usec = 0;
           ready = select(sock + 1, &descriptors, nullptr, nullptr, &tv);

           if (!ready){
               printf("\tRequest timed out.\n");
               break;
           }

           recv_len = sizeof(sockaddr_in);
           ret = recvfrom(sock, (char *)packet, MAX_ICMP_SIZE, 0,(struct sockaddr *)&from, (socklen_t*)&recv_len);

           if(ret < 0 && errno == EAGAIN){
               // timeout
               printf("\tRequest timed out.\n");
               i++;
               continue;
           } else if (ret < 0) {
               printf("Failed to recvfrom\n");
               return -1;
           }

           // Check the IP header
           ip_header = (struct ip *)((char*)packet);
           if (ret < (ip_header_len + ICMP_MINLEN)) {
               cerr << "packet too short (" << ret  << " bytes) from " << host_name << endl;;
               return -1;
           }

           // Now the ICMP part
           icp = (struct icmp *)(packet + ip_header->ip_hl * 4);

           src_ip = inet_ntoa(ip_header->ip_src);

           if (icp->icmp_type == ICMP_TIME_EXCEEDED && icp->icmp_code == ICMP_EXC_TTL){

               ip_header_inner = (struct ip *)(packet + ip_header->ip_hl * 4 + ICMP_HEADER_LEN);

               if (ip_header_inner->ip_p != IPPROTO_ICMP)
                   continue;

               icp_inner = (struct icmp *)(packet + ip_header->ip_hl * 4 + ICMP_HEADER_LEN + ip_header_inner->ip_hl * 4);

               if (icp_inner->icmp_id != getpid())
                   continue;

               if (icp_inner->icmp_seq != ttl)
                   continue;

           } else if(icp->icmp_type == ICMP_ECHOREPLY && icp->icmp_id == getpid()){
               reach_dest = src_ip == host_ip;
           }else{
               continue;
           }

           gettimeofday(&end, nullptr);
           double elapsedTime = (end.tv_sec - timers[i].tv_sec) * 1000.0;
           elapsedTime += (end.tv_usec - timers[i].tv_usec) / 1000.0;
           i++;

           printf("\t%s\t%.1lfms\n", src_ip.c_str(), elapsedTime);
           if (i == 3)
               break;
       }

       ttl++;
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
