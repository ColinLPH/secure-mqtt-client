#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 12345

ssize_t send_all(int sock, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

ssize_t recv_all(int sock, unsigned char *buf, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = recv(sock, buf + recvd, len - recvd, 0);
        if (n <= 0) return -1;
        recvd += n;
    }
    return recvd;
}

void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        printf("libsodium initialization failed\n");
        return 1;
    }

    if (argc < 2) {
        printf("Usage: %s <server_ip> [port]\n", argv[0]);
        return 1;
    }

    const char *serverIP = argv[1];
    int server_port = (argc >= 3) ? atoi(argv[2]) : PORT;

    printf("Connecting to %s:%d...\n", serverIP, server_port);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket failed"); return 1; }

    struct sockaddr_in servaddr = {0};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, serverIP, &servaddr.sin_addr) <= 0) {
        perror("Invalid server IP");
        close(sockfd);
        return 1;
    }

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect failed");
        close(sockfd);
        return 1;
    }

    // Generate client ephemeral key pair
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(client_pk, client_sk);
    print_hex("Client PK", client_pk, crypto_kx_PUBLICKEYBYTES);

    // Send client public key
    if (send_all(sockfd, client_pk, crypto_kx_PUBLICKEYBYTES) != crypto_kx_PUBLICKEYBYTES) {
        perror("send failed");
        close(sockfd);
        return 1;
    }

    // Receive server public key
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    if (recv_all(sockfd, server_pk, crypto_kx_PUBLICKEYBYTES) != crypto_kx_PUBLICKEYBYTES) {
        perror("recv failed");
        close(sockfd);
        return 1;
    }
    print_hex("Server PK", server_pk, crypto_kx_PUBLICKEYBYTES);

    // Derive shared secret
    unsigned char rx[crypto_kx_SESSIONKEYBYTES], tx[crypto_kx_SESSIONKEYBYTES];
    if (crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0) {
        printf("Failed to derive session keys\n");
        close(sockfd);
        return 1;
    }

    print_hex("Client RX (receive key)", rx, crypto_kx_SESSIONKEYBYTES);
    print_hex("Client TX (transmit key)", tx, crypto_kx_SESSIONKEYBYTES);

    close(sockfd);
    return 0;
}
