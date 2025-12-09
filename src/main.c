#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define PORT 12345
#define NONCE_SIZE crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define TAG_SIZE   crypto_aead_chacha20poly1305_ietf_ABYTES

//-------------------------------------------------------------
// Utils
//-------------------------------------------------------------
void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

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

//-------------------------------------------------------------
// Crypto helpers
//-------------------------------------------------------------
void ecdh_handshake(int sock,
                    unsigned char rx[],
                    unsigned char tx[])
{
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(client_pk, client_sk);

    send_all(sock, client_pk, sizeof(client_pk));

    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    recv_all(sock, server_pk, sizeof(server_pk));

    print_hex("Client PK", client_pk, sizeof(client_pk));
    print_hex("Server PK", server_pk, sizeof(server_pk));

    if (crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0) {
        printf("Session key derivation failed\n");
        exit(1);
    }

    print_hex("Client RX key", rx, crypto_kx_SESSIONKEYBYTES);
    print_hex("Client TX key", tx, crypto_kx_SESSIONKEYBYTES);
}

unsigned long long decrypt_message(
        const unsigned char *ciphertext, size_t ct_len,
        const unsigned char *nonce,
        const unsigned char *key,
        unsigned char *plaintext)
{
    unsigned long long pt_len = 0;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &pt_len,
            NULL,
            ciphertext, ct_len,
            NULL, 0,
            nonce, key) != 0)
    {
        printf("Decryption failed (tampered?)\n");
        exit(1);
    }

    return pt_len;
}

void receive_encrypted(int sock, const unsigned char *key) {
    uint32_t net_len;
    recv_all(sock, (unsigned char*)&net_len, sizeof(net_len));
    uint32_t ct_len = ntohl(net_len);

    unsigned char nonce[NONCE_SIZE];
    recv_all(sock, nonce, NONCE_SIZE);

    unsigned char ciphertext[ct_len];
    recv_all(sock, ciphertext, ct_len);

    unsigned char plaintext[ct_len];
    unsigned long long pt_len = decrypt_message(
        ciphertext, ct_len, nonce, key, plaintext);

    printf("Decrypted message (%llu bytes): ", pt_len);
    fwrite(plaintext, 1, pt_len, stdout);
    printf("\n");
}

//-------------------------------------------------------------
// Main
//-------------------------------------------------------------

int connect_to_server(const char *server_ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &addr.sin_addr);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    return sock;
}

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        printf("libsodium init failed\n");
        return 1;
    }

    if (argc < 2) {
        printf("Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];

    int sock = connect_to_server(server_ip, PORT);

    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];

    ecdh_handshake(sock, rx, tx);
    receive_encrypted(sock, rx);

    close(sock);
    return 0;
}
