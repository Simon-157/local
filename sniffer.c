#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/types.h>

#define BUFFER_SIZE 1024
void print_payload(const u_char *payload, int len) {
    int i;
    for (i = 0; i < len; i++) {
        printf("%02X ", payload[i]);
        if ((i + 1) % 16 == 0 || i == len - 1)
            printf("\n");
    }
}

void print_as_string(const u_char *payload, int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (isprint(payload[i]))
            putchar(payload[i]);
        else
            putchar('.');
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    const u_char *payload;
    int payload_len;

    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

        switch (ip_header->ip_p) {
            case IPPROTO_TCP:
                tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                printf("Protocol: TCP\n");
                printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
                printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
                break;
            case IPPROTO_UDP:
                udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                printf("Protocol: UDP\n");
                printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
                printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
                break;
            default:
                printf("Protocol: %d\n", ip_header->ip_p);
                break;
        }

        payload = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);
        payload_len = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

        printf("Payload Length: %d\n", payload_len);
        printf("Payload (hex): \n");
        print_payload(payload, payload_len);
        printf("\nPayload (ASCII): \n");
        print_as_string(payload, payload_len);
        printf("\n\n");
    }
}


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    // Find the network interface and its attributes
    if (pcap_lookupnet("tap0", &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Could not get network info: %s\n", errbuf);
        net = 0;
        mask = 0;
    }

    // Open the network interface for packet capture
    handle = pcap_open_live("tap0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device tap0: %s\n", errbuf);
        return 2;
    }

    // Compile and apply the packet filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Capture packets and call packet_handler for each packet
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
