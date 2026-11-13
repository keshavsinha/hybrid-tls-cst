/* Minimal blocking s2n-tls server: negotiate, report the outcome and its
   timing, then s2n_shutdown + close. Used to separate library behaviour
   from the s2nd demo server. */
#include <s2n.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char *slurp(const char *p) {
    FILE *f = fopen(p, "r"); if (!f) { perror(p); exit(1); }
    static char buf[2][8192]; static int i = 0; char *b = buf[i++];
    size_t n = fread(b, 1, 8191, f); b[n] = 0; fclose(f); return b;
}

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 9454;
    signal(SIGPIPE, SIG_IGN);
    s2n_init();
    struct s2n_config *cfg = s2n_config_new();
    struct s2n_cert_chain_and_key *ck = s2n_cert_chain_and_key_new();
    if (s2n_cert_chain_and_key_load_pem(ck, slurp("../cert.pem"), slurp("../key.pem")) ||
        s2n_config_add_cert_chain_and_key_to_store(cfg, ck) ||
        s2n_config_set_cipher_preferences(cfg, "default_pq")) {
        fprintf(stderr, "config: %s\n", s2n_strerror(s2n_errno, "EN")); return 1;
    }
    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(ls, (void *)&a, sizeof a) || listen(ls, 16)) { perror("bind"); return 1; }
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) continue;
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        s2n_connection_set_config(conn, cfg);
        s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING);
        s2n_connection_set_fd(conn, c);
        s2n_blocked_status blocked;
        struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
        int rc = s2n_negotiate(conn, &blocked);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        if (rc != S2N_SUCCESS)
            fprintf(stderr, "negotiate FAILED after %.2fs: %s (%s)\n", dt,
                    s2n_strerror(s2n_errno, "EN"), s2n_strerror_debug(s2n_errno, "EN"));
        else
            fprintf(stderr, "negotiate ok after %.2fs\n", dt);
        fflush(stderr);
        s2n_shutdown(conn, &blocked);
        s2n_connection_free(conn);
        close(c);
    }
}
