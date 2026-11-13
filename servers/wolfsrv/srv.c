/* Minimal looping wolfSSL TLS 1.3 server for the CST harness. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 9449;
    signal(SIGPIPE, SIG_IGN); /* client hangs up after ServerHello */
    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (wolfSSL_CTX_use_certificate_file(ctx, "../cert.pem", WOLFSSL_FILETYPE_PEM) != 1 ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, "../key.pem", WOLFSSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "cert/key load failed\n"); return 1;
    }
    int groups[] = {WOLFSSL_X25519MLKEM768, WOLFSSL_SECP256R1MLKEM768,
                    WOLFSSL_SECP384R1MLKEM1024, WOLFSSL_ECC_X25519};
    int rc = wolfSSL_CTX_set_groups(ctx, groups, 4);
    fprintf(stderr, "set_groups rc=%d\n", rc);
    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(ls, (void *)&a, sizeof a) || listen(ls, 16)) { perror("bind"); return 1; }
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) continue;
        WOLFSSL *ssl = wolfSSL_new(ctx);
        wolfSSL_set_fd(ssl, c);
        if (wolfSSL_accept(ssl) != 1)
            fprintf(stderr, "accept err %d\n", wolfSSL_get_error(ssl, 0));
        wolfSSL_free(ssl);
        close(c);
    }
}
