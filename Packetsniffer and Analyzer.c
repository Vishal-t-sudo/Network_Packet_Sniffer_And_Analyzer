#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define MAX_PACKETS 1000

// Function declarations
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_packet_info(const struct pcap_pkthdr *header, const u_char *packet);
void print_ethernet_header(const u_char *packet);
void print_ip_header(const u_char *packet);
void print_tcp_header(const u_char *packet);
void print_udp_header(const u_char *packet);

int main(int argc, char *argv[]) {
    pcap_t *handle;                 // Session handle
    char *dev = argv[1];            // Device to sniff on
    char errbuf[PCAP_ERRBUF_SIZE]; // Error string
    int packet_count = 0;           // Counter for number of packets captured

    // Check if the user provided the interface name
    if (argc != 2) {
        fprintf(stderr, "Usage: %s interface\n", argv[0]);
        return 1;
    }

    // Open the capture device
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Start capturing packets
    while (1) {
        struct pcap_pkthdr *header;
        const u_char *packet_data;
        int ret = pcap_next_ex(handle, &header, &packet_data);
        if (ret == 1) {
            packet_handler(NULL, header, packet_data);
            packet_count++;
            if (packet_count >= MAX_PACKETS)
                break;
        } else if (ret == -1) {
            fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(handle));
            break;
        } else if (ret == 0) {
            // Timeout elapsed
            continue;
        } else if (ret == -2) {
            // No more packets to read
            break;
        } else {
            // Other error
            fprintf(stderr, "Unknown error occurred while capturing packets\n");
            break;
        }
    }

    // Close the session
    pcap_close(handle);
    return 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Packet captured with length: %d\n", header->len);
    print_packet_info(header, packet);
    
}

void print_packet_info(const struct pcap_pkthdr *header, const u_char *packet) {
    
    printf("Packet captured with length: %d bytes\n", header->len);

    // Print out the timestamp of the packet
    printf("Timestamp: %ld.%06ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);

    // Print out the packet size
    printf("Packet size: %d bytes\n", header->caplen);

    // Print out the first few bytes of the packet data
    printf("First 10 bytes of packet data: ");

    for (int i = 0; i < 10; i++) {
        printf("%02X ", packet[i]);
    }
    printf("\n");
    
    print_ethernet_header(packet);
    print_ip_header(packet);
    print_tcp_header(packet);
    print_udp_header(packet);

}

void print_ethernet_header(const u_char *packet) {

    // Ethernet header is 14 bytes long
    // Extracting the destination MAC address
    printf("Destination MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);

    // Extracting the source MAC address
    printf("Source MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

    // Extracting the Ethernet type
    uint16_t ethernet_type = (packet[12] << 8) | packet[13];
    printf("Ethernet Type: %04X\n", ethernet_type);

}

void print_ip_header(const u_char *packet) {

    // Assuming IPv4 header
    // Extracting the IP version (4 bits) and header length (4 bits)
    uint8_t version_header_length = packet[0];
    uint8_t version = version_header_length >> 4; // First 4 bits represent the version
    uint8_t header_length = (version_header_length & 0x0F) * 4; // Next 4 bits represent the header length in 32-bit words

    // Extracting the Differentiated Services Field (8 bits)
    uint8_t differentiated_services = packet[1];

    // Extracting the Total Length (16 bits)
    uint16_t total_length = (packet[2] << 8) | packet[3];

    // Extracting the Identification (16 bits)
    uint16_t identification = (packet[4] << 8) | packet[5];

    // Extracting the Flags (3 bits) and Fragment Offset (13 bits)
    uint16_t flags_fragment_offset = (packet[6] << 8) | packet[7];
    uint8_t flags = (flags_fragment_offset >> 13) & 0x07;
    uint16_t fragment_offset = flags_fragment_offset & 0x1FFF;

    // Extracting the Time to Live (8 bits)
    uint8_t ttl = packet[8];

    // Extracting the Protocol (8 bits)
    uint8_t protocol = packet[9];

    // Extracting the Header Checksum (16 bits)
    uint16_t header_checksum = (packet[10] << 8) | packet[11];

    // Extracting the Source IP Address (32 bits)
    uint32_t source_ip_address = (packet[12] << 24) | (packet[13] << 16) | (packet[14] << 8) | packet[15];

    // Extracting the Destination IP Address (32 bits)
    uint32_t destination_ip_address = (packet[16] << 24) | (packet[17] << 16) | (packet[18] << 8) | packet[19];

    // Print out the IP header fields
    printf("IP Version: %d\n", version);
    printf("Header Length: %d bytes\n", header_length);
    printf("Differentiated Services Field: 0x%02X\n", differentiated_services);
    printf("Total Length: %d bytes\n", total_length);
    printf("Identification: 0x%04X\n", identification);
    printf("Flags: %d\n", flags);
    printf("Fragment Offset: %d\n", fragment_offset);
    printf("Time to Live: %d\n", ttl);
    printf("Protocol: %d\n", protocol);
    printf("Header Checksum: 0x%04X\n", header_checksum);
    printf("Source IP Address: %d.%d.%d.%d\n", (source_ip_address >> 24) & 0xFF, (source_ip_address >> 16) & 0xFF,
           (source_ip_address >> 8) & 0xFF, source_ip_address & 0xFF);
    printf("Destination IP Address: %d.%d.%d.%d\n", (destination_ip_address >> 24) & 0xFF,
           (destination_ip_address >> 16) & 0xFF, (destination_ip_address >> 8) & 0xFF, destination_ip_address & 0xFF);

}

void print_tcp_header(const u_char *packet) {

    // Assuming TCP header starts at byte 34
    const u_char *tcp_header = packet + 34;

    // Extracting the source port (16 bits)
    uint16_t source_port = (tcp_header[0] << 8) | tcp_header[1];

    // Extracting the destination port (16 bits)
    uint16_t destination_port = (tcp_header[2] << 8) | tcp_header[3];

    // Extracting the sequence number (32 bits)
    uint32_t sequence_number = (tcp_header[4] << 24) | (tcp_header[5] << 16) | (tcp_header[6] << 8) | tcp_header[7];

    // Extracting the acknowledgment number (32 bits)
    uint32_t acknowledgment_number = (tcp_header[8] << 24) | (tcp_header[9] << 16) | (tcp_header[10] << 8) | tcp_header[11];

    // Extracting the data offset (4 bits) and reserved bits (3 bits) and flags (9 bits) combined into a 16-bit field
    uint16_t data_offset_reserved_flags = (tcp_header[12] << 8) | tcp_header[13];
    uint8_t data_offset = (data_offset_reserved_flags >> 12) * 4; // Data offset is in 32-bit words, so we multiply by 4 to get bytes

    // Extracting the flags (9 bits)
    uint16_t flags = data_offset_reserved_flags & 0x1FF;

    // Extracting the window size (16 bits)
    uint16_t window_size = (tcp_header[14] << 8) | tcp_header[15];

    // Extracting the TCP checksum (16 bits)
    uint16_t checksum = (tcp_header[16] << 8) | tcp_header[17];

    // Extracting the urgent pointer (16 bits)
    uint16_t urgent_pointer = (tcp_header[18] << 8) | tcp_header[19];

    // Print out the TCP header fields
    printf("Source Port: %d\n", source_port);
    printf("Destination Port: %d\n", destination_port);
    printf("Sequence Number: %u\n", sequence_number);
    printf("Acknowledgment Number: %u\n", acknowledgment_number);
    printf("Data Offset: %d bytes\n", data_offset);
    printf("Flags: 0x%04X\n", flags);
    printf("Window Size: %d\n", window_size);
    printf("Checksum: 0x%04X\n", checksum);
    printf("Urgent Pointer: %d\n", urgent_pointer);

}

void print_udp_header(const u_char *packet) {

    // Assuming UDP header starts at byte 34
    const u_char *udp_header = packet + 34;

    // Extracting the source port (16 bits)
    uint16_t source_port = (udp_header[0] << 8) | udp_header[1];

    // Extracting the destination port (16 bits)
    uint16_t destination_port = (udp_header[2] << 8) | udp_header[3];

    // Extracting the length (16 bits)
    uint16_t length = (udp_header[4] << 8) | udp_header[5];

    // Extracting the checksum (16 bits)
    uint16_t checksum = (udp_header[6] << 8) | udp_header[7];

    // Print out the UDP header fields
    printf("Source Port: %d\n", source_port);
    printf("Destination Port: %d\n", destination_port);
    printf("Length: %d\n", length);
    printf("Checksum: 0x%04X\n", checksum);

}