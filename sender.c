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
#define PORT_NO 14000 // source port v data (net derper)
#define ACK_PORT_NO 15001 // target port v ack (net derper)
#define IP_ADDRESS "127.0.0.1"
#define TIMEOUT_SECONDS 2

typedef struct {
    uint32_t packet_number;
    uint8_t termination_flag;
    uint16_t data_size;
    char data[PACKET_MAX_DATA_SIZE];
    uint32_t crc;
} Packet;

typedef struct {
    uint32_t packet_number;
    uint8_t ack_flag; // 1 for ACK, 0 for NACK
    uint32_t crc;
} AckPacket;

typedef struct {
    uint32_t packet_number;
    uint16_t data_size;
    char hash[MD5_DIGEST_LENGTH * 2 + 1];
    uint32_t crc;
} HashPacket;

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

// Function to receive ACK/NACK
int receive_ack(int ack_sock, struct sockaddr_in ack_con, uint32_t packet_number) {
    AckPacket ack_packet;
    int ack_addrlen = sizeof(ack_con);
    int n = recvfrom(ack_sock, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr*)&ack_con, &ack_addrlen);

    if (n > 0) {
        uint32_t computed_crc = crc32(0L, (const Bytef*)&ack_packet.packet_number, sizeof(ack_packet.packet_number) + sizeof(ack_packet.ack_flag));
        if (ack_packet.crc == computed_crc && ack_packet.packet_number == packet_number) {
            return ack_packet.ack_flag;
        }
    }

    return -1; // Timeout or invalid ACK/NACK
}

// Function to send hash packet
void send_hash_packet(int sockfd, struct sockaddr_in addr_con, uint32_t packet_number, const char* hash) {
    HashPacket hash_packet;
    hash_packet.packet_number = packet_number;
    strncpy(hash_packet.hash, hash, MD5_DIGEST_LENGTH * 2 + 1);
    hash_packet.data_size = strlen(hash_packet.hash);
    hash_packet.crc = crc32(0L, (const Bytef*)&hash_packet.packet_number, sizeof(hash_packet.packet_number) + sizeof(hash_packet.data_size) + hash_packet.data_size);

    sendto(sockfd, &hash_packet, sizeof(hash_packet), 0, (struct sockaddr*)&addr_con, sizeof(addr_con));
}

// Function to send a file using Stop-and-Wait protocol
void send_file(const char* file_name, int sockfd, int ack_sock, struct sockaddr_in addr_con, struct sockaddr_in ack_con) {
    FILE* fp = fopen(file_name, "rb");
    if (!fp) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    Packet packet;
    int addrlen = sizeof(addr_con);
    int ack_addrlen = sizeof(ack_con);
    uint32_t packet_number = 0;
    size_t bytes_read;
    char response[4];
    struct timeval timeout = {TIMEOUT_SECONDS, 0};

    // Set socket timeout
    if (setsockopt(ack_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Failed to set socket timeout");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    // Compute file hash
    char file_hash[MD5_DIGEST_LENGTH * 2 + 1] = {0};
    compute_file_md5(file_name, file_hash);

    // Send the file hash to the receiver
    send_hash_packet(sockfd, addr_con, packet_number, file_hash);

    // Wait for ACK for the hash packet
    int hash_ack_received = 0;
    int tries = 0;
    while (!hash_ack_received && tries < 10) {
        int ack_flag = receive_ack(ack_sock, ack_con, 0);
        if (ack_flag == 1) {
            printf("File hash ACK received.\n");
            hash_ack_received = 1;
        } else {
            printf("Resending file hash due to timeout or NACK.\n");
            send_hash_packet(sockfd, addr_con, packet_number, file_hash);
        }
        tries++;
    }

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
            int ack_flag = receive_ack(ack_sock, ack_con, packet_number);
            if (ack_flag == 1) {
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
    int termination_ack_received = 0;
    int retry_count = 0;
    const int MAX_RETRIES = 5;

    while (!termination_ack_received && retry_count < MAX_RETRIES) {
        packet.termination_flag = 1;
        strcpy(packet.data, "STOP");
        packet.data_size = strlen(packet.data);
        packet.crc = crc32(0L, (const Bytef*)&packet.packet_number, sizeof(packet.packet_number) + sizeof(packet.termination_flag) + sizeof(packet.data) + sizeof(packet.data_size));
        sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&addr_con, addrlen);

        // Wait for ACK/NACK for termination packet
        int ack_flag = receive_ack(ack_sock, ack_con, packet_number);
        if (ack_flag == 1) {
            termination_ack_received = 1;
            printf("Termination packet: ACK received\n");
        } else {
            printf("Termination packet: Resending due to timeout or NACK\n");
        }

        retry_count++;
    }

    if (retry_count == MAX_RETRIES) {
        printf("Termination packet: Max retries reached. Exiting.\n");
    }

    printf("File transfer complete.\n");
    fclose(fp);
}

int main() {
    int sockfd, ack_sock;
    struct sockaddr_in addr_con, ack_con;

    // Create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    addr_con.sin_family = AF_INET;
    addr_con.sin_port = htons(PORT_NO);
    addr_con.sin_addr.s_addr = inet_addr(IP_ADDRESS);

    // Create ack socket
    ack_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ack_sock < 0) {
        perror("ACK socket creation failed");
        exit(EXIT_FAILURE);
    }

    ack_con.sin_family = AF_INET;
    ack_con.sin_port = htons(ACK_PORT_NO);
    ack_con.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&ack_con, sizeof(ack_con)) < 0) {
        perror("Bind failed");
        close(sockfd);
        close(ack_sock);
        exit(EXIT_FAILURE);
    }

    char file_name[256];
    printf("Enter the file name to send: ");
    scanf("%s", file_name);

    send_file(file_name, sockfd, sockfd, addr_con, ack_con);

    close(sockfd);
    close(ack_sock);
    return 0;
}