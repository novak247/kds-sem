#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>  // For CRC32
#include <openssl/md5.h>  // For file hash

#define PACKET_MAX_SIZE 1024
#define PACKET_MAX_DATA_SIZE 1024 - 2*sizeof(uint32_t) - sizeof(uint8_t) - sizeof(uint16_t)
#define PORT_NO 15050
#define IP_ADDRESS "192.168.1.178"
#define TIMEOUT_SECONDS 2

typedef struct {
    uint32_t packet_number;
    uint8_t termination_flag;
    uint16_t data_size;
    char data[PACKET_MAX_DATA_SIZE];
    uint32_t crc;
} Packet;

// Function to calculate MD5 hash of a file
void compute_file_md5(const char* file_name, char* hash_str) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5_ctx;
    FILE* fp = fopen(file_name, "rb");
    if (!fp) {
        perror("Failed to open file for MD5 computation");
        exit(EXIT_FAILURE);
    }

    MD5_Init(&md5_ctx);
    char buffer[PACKET_MAX_DATA_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, PACKET_MAX_DATA_SIZE, fp)) > 0) {
        MD5_Update(&md5_ctx, buffer, bytes_read);
    }
    fclose(fp);

    MD5_Final(hash, &md5_ctx);

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }
}

// Function to send a file using Stop-and-Wait protocol
void send_file(const char* file_name, int sockfd, struct sockaddr_in addr_con) {
    FILE* fp = fopen(file_name, "rb");
    if (!fp) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    Packet packet;
    int addrlen = sizeof(addr_con);
    uint32_t packet_number = 0;
    size_t bytes_read;
    char response[4];
    struct timeval timeout = {TIMEOUT_SECONDS, 0};

    // Set socket timeout
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Failed to set socket timeout");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    // Compute file hash
    char file_hash[MD5_DIGEST_LENGTH * 2 + 1] = {0};
    compute_file_md5(file_name, file_hash);

    // Send the file hash to the receiver
    sendto(sockfd, file_hash, strlen(file_hash), 0, (struct sockaddr*)&addr_con, addrlen);

    // Send file packets
    while ((bytes_read = fread(packet.data, 1, PACKET_MAX_DATA_SIZE, fp)) > 0) {
        packet.packet_number = packet_number;
        packet.termination_flag = 0;
        packet.data_size = bytes_read;
        printf("%d \n", bytes_read);
        printf("1\n");
        printf("%d\n", sizeof(packet.packet_number) + sizeof(packet.termination_flag) + sizeof(packet.data));
        packet.crc = crc32(0L, (const Bytef*)&packet.packet_number, sizeof(packet.packet_number) + sizeof(packet.termination_flag) + sizeof(packet.data) + sizeof(packet.data_size));//bytes_read
        printf("crc: %d\n", packet.crc);
        
        printf("2\n");
        int ack_received = 0;
        while (!ack_received) {
            // Send the packet
            sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&addr_con, addrlen);
            printf("3\n");
            // Wait for ACK/NACK
            int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr*)&addr_con, &addrlen);
            printf("4\n");
            if (n > 0 && strncmp(response, "ACK", 3) == 0) {
                ack_received = 1;
                printf("Packet %u: ACK received\n", packet_number);
            } else {
                printf("Packet %u: Resending due to timeout or NACK\n", packet_number);
            }
        }

        packet_number++;
    }
    printf("5\n");
    // Send termination packet
    strcpy(packet.data, "STOP");
    packet.crc = crc32(0L, (const Bytef*)&packet.packet_number, sizeof(packet.packet_number) + sizeof(packet.termination_flag) + sizeof(packet.data) + sizeof(packet.data_size));//bytes_read
    packet.termination_flag = 1;
    sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&addr_con, addrlen);
    // Packet termination_packet;
    // termination_packet.packet_number = 0;
    // termination_packet.termination_flag = 1;
    // strcpy(termination_packet.data, "STOP");
    // termination_packet.crc = crc32(0L, (const Bytef*)packet.data, bytes_read);


    printf("File transfer complete.\n");
    fclose(fp);
}

int main() {
    int sockfd;
    struct sockaddr_in addr_con;

    // Create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    addr_con.sin_family = AF_INET;
    addr_con.sin_port = htons(PORT_NO);
    addr_con.sin_addr.s_addr = inet_addr(IP_ADDRESS);

    char file_name[256];
    printf("Enter the file name to send: ");
    scanf("%s", file_name);

    send_file(file_name, sockfd, addr_con);

    close(sockfd);
    return 0;
}