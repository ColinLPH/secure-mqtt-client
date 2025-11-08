#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 12345

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        printf("libsodium initialization failed\n");
        return 1;
    }

    if (argc < 2) {
        printf("Usage: %s <server_ip> [port default 12345]\n", argv[0]);
        return 1;
    }

    const char *serverIP = argv[1];
    int server_port = (argc >= 3) ? atoi(argv[2]) : PORT;

    printf("Connecting to %s:%d...\n", serverIP, server_port);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        return 1;
    }

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

    // Send client public key to server
    if (send(sockfd, client_pk, crypto_kx_PUBLICKEYBYTES, 0) != crypto_kx_PUBLICKEYBYTES) {
        perror("send failed");
        close(sockfd);
        return 1;
    }

    // Receive server public key
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    if (recv(sockfd, server_pk, crypto_kx_PUBLICKEYBYTES, 0) != crypto_kx_PUBLICKEYBYTES) {
        perror("recv failed");
        close(sockfd);
        return 1;
    }

    // Derive shared secret
    unsigned char rx[crypto_kx_SESSIONKEYBYTES], tx[crypto_kx_SESSIONKEYBYTES];
    if (crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0) {
        printf("Failed to derive session keys\n");
        close(sockfd);
        return 1;
    }

    printf("Shared secret (rx) for encryption:\n");
    for (int i = 0; i < crypto_kx_SESSIONKEYBYTES; i++)
        printf("%02x", rx[i]);
    printf("\n");

    close(sockfd);
    return 0;
}
