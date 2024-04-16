#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>

#define PORT 8888
#define BUFFER_SIZE 1024

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ethhdr) + iph->ihl * 4);
    const u_char *payload = packet + sizeof(struct ethhdr) + iph->ihl * 4 + tcph->doff * 4;

    // Extract relevant information
    char *src_ip = inet_ntoa(*(struct in_addr *)&iph->saddr);
    char *dst_ip = inet_ntoa(*(struct in_addr *)&iph->daddr);
    int src_port = ntohs(tcph->source);
    int dst_port = ntohs(tcph->dest);

    // Print packet information
    printf("Packet received: ");
    printf("Src IP: %s, Src Port: %d, ", src_ip, src_port);
    printf("Dst IP: %s, Dst Port: %d, ", dst_ip, dst_port);
    printf("Payload Length: %d\n", header->len - sizeof(struct ethhdr) - iph->ihl * 4 - tcph->doff * 4);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open network interface for packet capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf); // Replace "eth0" with your network interface
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
        return EXIT_FAILURE;
    }

    // Set filter to capture only TCP packets on the specified port
    struct bpf_program fp;
    char filter_exp[100];
    sprintf(filter_exp, "tcp port %d", PORT);
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    printf("Monitoring started...\n");

    // Start capturing packets
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
