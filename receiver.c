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

#define PACKET_MAX_DATA_SIZE 1024 -2*sizeof(uint32_t)-sizeof(uint8_t)-sizeof(uint16_t)   
#define PORT_NO 15050
#define SENDRECV_FLAG 0

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

// Function to receive a file using Stop-and-Wait protocol
void receive_file(int sockfd, struct sockaddr_in addr_con) {
    FILE* fp = fopen("received_file", "wb");
    if (!fp) {
        perror("Failed to open file for writing");
        exit(EXIT_FAILURE);
    }

    Packet packet;
    int addrlen = sizeof(addr_con);
    uint32_t expected_packet = 0;
    char file_hash[MD5_DIGEST_LENGTH * 2 + 1] = {0};
    char received_hash[MD5_DIGEST_LENGTH * 2 + 1] = {0};

    // Receive file hash
    if (recvfrom(sockfd, received_hash, sizeof(received_hash), 0, (struct sockaddr*)&addr_con, &addrlen) < 0) {
        perror("Failed to receive file hash");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    printf("Expected file hash: %s\n", received_hash);

    while (1) {
        memset(&packet, 0, sizeof(packet));
        int nBytes = recvfrom(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&addr_con, &addrlen);

        if (nBytes < 0) {
            perror("Failed to receive packet");
            break;
        }

        // Check for termination packet
        if (packet.termination_flag == 1) {
            printf("Termination packet received. Ending transfer.\n");
            break;
        }

        // Validate CRC
        uint32_t computed_crc = crc32(0L, (const Bytef*)&packet.packet_number, sizeof(packet.packet_number) + sizeof(packet.termination_flag) + sizeof(packet.data) + sizeof(packet.data_size));
        if (computed_crc != packet.crc) {
            printf("crc exp: %d, crc calc: %d", computed_crc, packet.crc);
            printf("Packet %u failed CRC check. Sending NACK.\n", packet.packet_number);
            sendto(sockfd, "NACK", 4, 0, (struct sockaddr*)&addr_con, addrlen);
            continue;   
        }

        // Handle duplicate packets
        if (packet.packet_number != expected_packet) {
            printf("Duplicate or out-of-order packet %u received. Sending ACK.\n", packet.packet_number);
            sendto(sockfd, "ACK", 3, 0, (struct sockaddr*)&addr_con, addrlen);
            continue;
        }

        // Write data to file
        fwrite(packet.data, 1, packet.data_size, fp);
        printf("Packet %u received and written successfully. Sending ACK.\n", packet.packet_number);

        // Send ACK
        sendto(sockfd, "ACK", 3, 0, (struct sockaddr*)&addr_con, addrlen);
        expected_packet++;
    }

    fclose(fp);

    // Compute and validate file hash
    char computed_hash[MD5_DIGEST_LENGTH * 2 + 1] = {0};
    compute_file_md5("received_file", computed_hash);
    printf("Computed file hash: %s\n", computed_hash);

    if (strcmp(computed_hash, received_hash) == 0) {
        printf("File transfer successful. Hash matches.\n");
    } else {
        printf("File transfer failed. Hash mismatch.\n");
    }
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
    addr_con.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket
    if (bind(sockfd, (struct sockaddr*)&addr_con, sizeof(addr_con)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Waiting for file...\n");
    receive_file(sockfd, addr_con);

    close(sockfd);
    return 0;
}
