// tls_session.c - TLS 会话管理
#include "tls_types.h"
#include <string.h>
#include <stdio.h>

void tls_session_init(tls_session_t *session, int socket_fd) {
    memset(session, 0, sizeof(tls_session_t));
    session->socket_fd = socket_fd;
    session->encryption_enabled = 0;
    session->client_seq_num = 0;
    session->server_seq_num = 0;
    session->handshake_messages_len = 0;

    printf("[TLS] Session initialized\n");
}

void tls_session_cleanup(tls_session_t *session) {
    // 清理敏感数据
    memset(session->master_secret, 0, sizeof(session->master_secret));
    memset(session->client_write_key, 0, sizeof(session->client_write_key));
    memset(session->server_write_key, 0, sizeof(session->server_write_key));

    printf("[TLS] Session cleaned up\n");
}

