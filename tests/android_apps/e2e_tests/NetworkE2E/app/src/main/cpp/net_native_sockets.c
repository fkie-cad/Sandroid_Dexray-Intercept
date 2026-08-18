#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <pthread.h>
#include <poll.h>
#include <sys/un.h>

#define LOG_TAG "NET_NATIVE_SOCKETS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * Exercises libc socket syscalls hooked in sockets.ts via safeAttachExport:
 *
 *   send()     -> "Libc::send"
 *   recv()     -> "Libc::recv"
 *   sendmsg()  -> "Libc::sendmsg"
 *   recvmsg()  -> "Libc::recvmsg"
 *   close()    -> "Libc::close"
 *
 * Each test creates a loopback TCP pair in a single thread:
 *   listen() with backlog >= 1 -> connect() (kernel buffers it) -> accept()
 * This avoids pthreads while still producing real AF_INET sockets that
 * pass the hooks' type-filter (not "unix:stream").
 */

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, name) do { \
    if (cond) { \
        LOGI("  PASS: %s", (name)); \
        tests_passed++; \
    } else { \
        LOGE("  FAIL: %s  (errno=%d)", (name), errno); \
        tests_failed++; \
    } \
} while (0)

typedef ssize_t (*direct_send_fn)(
    int sockfd,
    const void *buf,
    size_t len,
    int flags
);

typedef ssize_t (*direct_recv_fn)(
    int sockfd,
    void *buf,
    size_t len,
    int flags
);

/* ------------------------------------------------------------------ */
/* Filesystem-namespace LocalSocket test server                       */
/*                                                                    */
/* LocalServerSocket(String) creates an abstract-namespace listener.  */
/* This native helper provides a realistic AF_UNIX filesystem server  */
/* so Java LocalSocket.connect(..., Namespace.FILESYSTEM) can be      */
/* exercised deterministically.                                      */
/* ------------------------------------------------------------------ */

static pthread_t filesystem_local_server_thread;
static int filesystem_local_server_started = 0;
static int filesystem_local_server_listener = -1;
static int filesystem_local_server_result = -1;
static char filesystem_local_server_path[
    sizeof(((struct sockaddr_un *)0)->sun_path)
];

static void *filesystem_local_server_main(void *unused) {
    (void)unused;

    struct pollfd poll_fd;
    poll_fd.fd = filesystem_local_server_listener;
    poll_fd.events = POLLIN;
    poll_fd.revents = 0;

    int poll_result = poll(&poll_fd, 1, 5000);
    if (poll_result <= 0) {
        LOGE(
            "filesystem LocalSocket server: poll failed or timed out, result=%d errno=%d",
            poll_result,
            errno
        );
        goto cleanup;
    }

    int client_fd = accept(filesystem_local_server_listener, NULL, NULL);
    if (client_fd < 0) {
        LOGE(
            "filesystem LocalSocket server: accept failed, errno=%d",
            errno
        );
        goto cleanup;
    }

    char buffer[64];
    ssize_t received = read(client_fd, buffer, sizeof(buffer));

    if (received > 0) {
        filesystem_local_server_result = 0;
        LOGI(
            "filesystem LocalSocket server received %zd bytes",
            received
        );
    } else {
        LOGE(
            "filesystem LocalSocket server read failed, result=%zd errno=%d",
            received,
            errno
        );
    }

    close(client_fd);

cleanup:
    if (filesystem_local_server_listener >= 0) {
        close(filesystem_local_server_listener);
        filesystem_local_server_listener = -1;
    }

    if (filesystem_local_server_path[0] != '\0') {
        unlink(filesystem_local_server_path);
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Helper: create a connected loopback TCP pair in one thread.         */
/*   *cli_fd  -> connected client side                                  */
/*   *srv_fd  -> accepted server side                                   */
/* Returns 0 on success, -1 on failure (fds are closed on failure).   */
/* ------------------------------------------------------------------ */
static int make_loopback_pair(int *cli_fd, int *srv_fd) {
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    int lsn = socket(AF_INET, SOCK_STREAM, 0);
    if (lsn < 0) {
        LOGE("make_loopback_pair: socket(listen) failed, errno=%d", errno);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;   /* OS picks a free port */

    if (bind(lsn, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOGE("make_loopback_pair: bind failed, errno=%d", errno);
        close(lsn);
        return -1;
    }
    if (listen(lsn, 2) < 0) {
        LOGE("make_loopback_pair: listen failed, errno=%d", errno);
        close(lsn);
        return -1;
    }

    /* Read back the OS-assigned port */
    if (getsockname(lsn, (struct sockaddr *)&addr, &addrlen) < 0) {
        LOGE("make_loopback_pair: getsockname failed, errno=%d", errno);
        close(lsn);
        return -1;
    }

    int cli = socket(AF_INET, SOCK_STREAM, 0);
    if (cli < 0) {
        LOGE("make_loopback_pair: socket(client) failed, errno=%d", errno);
        close(lsn);
        return -1;
    }

    /* connect() completes because the kernel holds the SYN in the backlog */
    if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOGE("make_loopback_pair: connect failed, errno=%d", errno);
        close(cli);
        close(lsn);
        return -1;
    }

    int srv = accept(lsn, NULL, NULL);
    if (srv < 0) {
        LOGE("make_loopback_pair: accept failed, errno=%d", errno);
        close(cli);
        close(lsn);
        return -1;
    }

    close(lsn);
    *cli_fd = cli;
    *srv_fd = srv;
    return 0;
}

static void test_socket_created_only(void) {
    LOGI("");
    LOGI("=== Native socket tests: direct socket creation ===");

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    TEST_ASSERT(fd >= 0, "socket() direct creation");

    if (fd >= 0) {
        int rc = close(fd);
        TEST_ASSERT(rc == 0, "close() direct-created socket");
    }
}

/* ------------------------------------------------------------------ */
/* Test 1: send() / recv()                                             */
/*                                                                     */
/* sockets.ts hooks:                                                   */
/*   send  -> "Libc::send"                                              */
/*   recv  -> "Libc::recv"                                              */
/*                                                                     */
/* Data is exchanged in both directions to exercise both syscalls      */
/* on both fds of the pair.                                            */
/* ------------------------------------------------------------------ */
static void test_send_recv(void) {
    LOGI("");
    LOGI("=== Native socket tests: send / recv ===");

    int cli = -1, srv = -1;
    if (make_loopback_pair(&cli, &srv) != 0) {
        TEST_ASSERT(0, "make_loopback_pair for send/recv");
        return;
    }
    TEST_ASSERT(1, "make_loopback_pair for send/recv");

    /* send() from client -> server */
    const char *msg = "send-recv-payload";
    ssize_t sent = send(cli, msg, strlen(msg), 0);
    LOGI("send(%d, \"%s\", %zu, 0) -> %zd", cli, msg, strlen(msg), sent);
    TEST_ASSERT(sent == (ssize_t)strlen(msg), "send() returned correct byte count");

    /* recv() on server */
    char buf[64];
    memset(buf, 0, sizeof(buf));
    ssize_t rcvd = recv(srv, buf, sizeof(buf) - 1, 0);
    LOGI("recv(%d, buf, %zu, 0) -> %zd, data=\"%s\"", srv, sizeof(buf) - 1, rcvd, buf);
    TEST_ASSERT(rcvd == sent, "recv() returned same byte count as send()");
    TEST_ASSERT(memcmp(buf, msg, (size_t)rcvd) == 0, "recv() data matches sent payload");

    /* send() from server -> client (reverse direction) */
    const char *reply = "reply-payload";
    ssize_t sent2 = send(srv, reply, strlen(reply), 0);
    LOGI("send(%d, \"%s\", %zu, 0) -> %zd", srv, reply, strlen(reply), sent2);
    TEST_ASSERT(sent2 == (ssize_t)strlen(reply), "send() reply returned correct byte count");

    /* recv() on client */
    char buf2[64];
    memset(buf2, 0, sizeof(buf2));
    ssize_t rcvd2 = recv(cli, buf2, sizeof(buf2) - 1, 0);
    LOGI("recv(%d, buf2, %zu, 0) -> %zd, data=\"%s\"", cli, sizeof(buf2) - 1, rcvd2, buf2);
    TEST_ASSERT(rcvd2 == sent2, "recv() reply returned correct byte count");
    TEST_ASSERT(memcmp(buf2, reply, (size_t)rcvd2) == 0, "recv() reply data matches");

    close(cli);
    close(srv);
}

/* ------------------------------------------------------------------ */
/* Test 1b: direct dlsym() send() / recv() exports                    */
/*                                                                     */
/* The NDK headers on current Android toolchains may lower ordinary    */
/* send() and recv() calls to sendto() and recvfrom(). This test calls */
/* the libc exports resolved by dlsym() so the hooks can be verified   */
/* against actual send() and recv() dispatch.                          */
/* ------------------------------------------------------------------ */
static void test_dlsym_send_recv(void) {
    LOGI("");
    LOGI("=== Native socket tests: dlsym send / recv ===");

    void *send_symbol = dlsym(RTLD_DEFAULT, "send");
    void *recv_symbol = dlsym(RTLD_DEFAULT, "recv");

    TEST_ASSERT(send_symbol != NULL, "dlsym() resolved send");
    TEST_ASSERT(recv_symbol != NULL, "dlsym() resolved recv");

    if (send_symbol == NULL || recv_symbol == NULL) {
        return;
    }

    direct_send_fn direct_send = (direct_send_fn)send_symbol;
    direct_recv_fn direct_recv = (direct_recv_fn)recv_symbol;

    int cli = -1;
    int srv = -1;

    if (make_loopback_pair(&cli, &srv) != 0) {
        TEST_ASSERT(0, "make_loopback_pair for dlsym send/recv");
        return;
    }
    TEST_ASSERT(1, "make_loopback_pair for dlsym send/recv");

    const char *message = "dlsym-send-payload";
    ssize_t sent = direct_send(cli, message, strlen(message), 0);

    LOGI(
        "dlsym send(%d, \"%s\", %zu, 0) -> %zd",
        cli,
        message,
        strlen(message),
        sent
    );
    TEST_ASSERT(
        sent == (ssize_t)strlen(message),
        "dlsym send() returned correct byte count"
    );

    char receive_buffer[64];
    memset(receive_buffer, 0, sizeof(receive_buffer));

    ssize_t received = direct_recv(
        srv,
        receive_buffer,
        sizeof(receive_buffer) - 1,
        0
    );

    LOGI(
        "dlsym recv(%d, buf, %zu, 0) -> %zd, data=\"%s\"",
        srv,
        sizeof(receive_buffer) - 1,
        received,
        receive_buffer
    );
    TEST_ASSERT(
        received == sent,
        "dlsym recv() returned same byte count as send()"
    );
    TEST_ASSERT(
        memcmp(receive_buffer, message, (size_t)received) == 0,
        "dlsym recv() data matches sent payload"
    );

    const char *reply = "dlsym-reply-payload";
    ssize_t sent_reply = direct_send(srv, reply, strlen(reply), 0);

    LOGI(
        "dlsym send(%d, \"%s\", %zu, 0) -> %zd",
        srv,
        reply,
        strlen(reply),
        sent_reply
    );
    TEST_ASSERT(
        sent_reply == (ssize_t)strlen(reply),
        "dlsym send() reply returned correct byte count"
    );

    char reply_buffer[64];
    memset(reply_buffer, 0, sizeof(reply_buffer));

    ssize_t received_reply = direct_recv(
        cli,
        reply_buffer,
        sizeof(reply_buffer) - 1,
        0
    );

    LOGI(
        "dlsym recv(%d, reply, %zu, 0) -> %zd, data=\"%s\"",
        cli,
        sizeof(reply_buffer) - 1,
        received_reply,
        reply_buffer
    );
    TEST_ASSERT(
        received_reply == sent_reply,
        "dlsym recv() reply returned same byte count as send()"
    );
    TEST_ASSERT(
        memcmp(reply_buffer, reply, (size_t)received_reply) == 0,
        "dlsym recv() reply data matches"
    );

    close(cli);
    close(srv);
}

/* ------------------------------------------------------------------ */
/* Test 2: sendmsg() / recvmsg()                                       */
/*                                                                     */
/* sockets.ts hooks:                                                   */
/*   sendmsg -> "Libc::sendmsg"                                         */
/*   recvmsg -> "Libc::recvmsg"                                         */
/*                                                                     */
/* A two-element iovec is used on both the send and receive sides to   */
/* exercise the scatter/gather path of both syscalls.                  */
/* ------------------------------------------------------------------ */
static void test_sendmsg_recvmsg(void) {
    LOGI("");
    LOGI("=== Native socket tests: sendmsg / recvmsg ===");

    int cli = -1, srv = -1;
    if (make_loopback_pair(&cli, &srv) != 0) {
        TEST_ASSERT(0, "make_loopback_pair for sendmsg/recvmsg");
        return;
    }
    TEST_ASSERT(1, "make_loopback_pair for sendmsg/recvmsg");

    /* sendmsg: gather two buffers into one message */
    const char *part1 = "sendmsg-";
    const char *part2 = "payload";
    struct iovec send_iov[2];
    send_iov[0].iov_base = (void *)part1;
    send_iov[0].iov_len  = strlen(part1);
    send_iov[1].iov_base = (void *)part2;
    send_iov[1].iov_len  = strlen(part2);

    struct msghdr send_hdr;
    memset(&send_hdr, 0, sizeof(send_hdr));
    send_hdr.msg_iov    = send_iov;
    send_hdr.msg_iovlen = 2;

    ssize_t sent = sendmsg(cli, &send_hdr, 0);
    size_t expected_len = strlen(part1) + strlen(part2);
    LOGI("sendmsg(%d, {iov=[%zu,\"%s\"],[%zu,\"%s\"]}, 0) -> %zd",
         cli,
         strlen(part1), part1,
         strlen(part2), part2,
         sent);
    TEST_ASSERT(sent == (ssize_t)expected_len,
                "sendmsg() returned correct total byte count");

    /* recvmsg: scatter into two receive buffers */
    char rbuf1[16];
    char rbuf2[16];
    memset(rbuf1, 0, sizeof(rbuf1));
    memset(rbuf2, 0, sizeof(rbuf2));

    struct iovec recv_iov[2];
    recv_iov[0].iov_base = rbuf1;
    recv_iov[0].iov_len  = strlen(part1);
    recv_iov[1].iov_base = rbuf2;
    recv_iov[1].iov_len  = sizeof(rbuf2) - 1;

    struct msghdr recv_hdr;
    memset(&recv_hdr, 0, sizeof(recv_hdr));
    recv_hdr.msg_iov    = recv_iov;
    recv_hdr.msg_iovlen = 2;

    ssize_t rcvd = recvmsg(srv, &recv_hdr, 0);
    LOGI("recvmsg(%d, ..., 0) -> %zd, rbuf1=\"%s\" rbuf2=\"%s\"",
         srv, rcvd, rbuf1, rbuf2);
    TEST_ASSERT(rcvd == (ssize_t)expected_len,
                "recvmsg() returned same byte count as sendmsg()");
    TEST_ASSERT(memcmp(rbuf1, part1, strlen(part1)) == 0,
                "recvmsg() scatter buf1 matches part1");
    TEST_ASSERT(memcmp(rbuf2, part2, strlen(part2)) == 0,
                "recvmsg() scatter buf2 matches part2");

    /* Reverse direction: sendmsg server -> client */
    const char *rpart1 = "resp-";
    const char *rpart2 = "msg";
    struct iovec rsend_iov[2];
    rsend_iov[0].iov_base = (void *)rpart1;
    rsend_iov[0].iov_len  = strlen(rpart1);
    rsend_iov[1].iov_base = (void *)rpart2;
    rsend_iov[1].iov_len  = strlen(rpart2);

    struct msghdr rsend_hdr;
    memset(&rsend_hdr, 0, sizeof(rsend_hdr));
    rsend_hdr.msg_iov    = rsend_iov;
    rsend_hdr.msg_iovlen = 2;

    ssize_t rsent = sendmsg(srv, &rsend_hdr, 0);
    size_t rexpected = strlen(rpart1) + strlen(rpart2);
    LOGI("sendmsg(%d, reverse, 0) -> %zd", srv, rsent);
    TEST_ASSERT(rsent == (ssize_t)rexpected,
                "sendmsg() reverse returned correct byte count");

    char rrbuf[32];
    memset(rrbuf, 0, sizeof(rrbuf));
    struct iovec rrecv_iov[1];
    rrecv_iov[0].iov_base = rrbuf;
    rrecv_iov[0].iov_len  = sizeof(rrbuf) - 1;

    struct msghdr rrecv_hdr;
    memset(&rrecv_hdr, 0, sizeof(rrecv_hdr));
    rrecv_hdr.msg_iov    = rrecv_iov;
    rrecv_hdr.msg_iovlen = 1;

    ssize_t rrcvd = recvmsg(cli, &rrecv_hdr, 0);
    LOGI("recvmsg(%d, reverse, 0) -> %zd, data=\"%s\"", cli, rrcvd, rrbuf);
    TEST_ASSERT(rrcvd == (ssize_t)rexpected,
                "recvmsg() reverse returned correct byte count");

    close(cli);
    close(srv);
}

/* ------------------------------------------------------------------ */
/* Test 2b: sendmsg() / recvmsg() with UDP msg_name                  */
/*                                                                     */
/* Exercises explicit sockaddr_in handling through msghdr.msg_name.   */
/* The sender remains unconnected, so sendmsg() must use msg_name for */
/* its destination and recvmsg() must recover the source from its     */
/* output msg_name.                                                    */
/* ------------------------------------------------------------------ */
static void test_sendmsg_recvmsg_udp(void) {
    LOGI("");
    LOGI("=== Native socket tests: sendmsg / recvmsg (UDP msg_name) ===");

    int recv_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(recv_fd >= 0, "socket() receiver for UDP sendmsg/recvmsg");
    if (recv_fd < 0) {
        return;
    }

    struct sockaddr_in recv_addr;
    socklen_t recv_addrlen = sizeof(recv_addr);
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    recv_addr.sin_port = 0;

    int rc = bind(
        recv_fd,
        (struct sockaddr *)&recv_addr,
        sizeof(recv_addr)
    );
    TEST_ASSERT(rc == 0, "bind() receiver for UDP sendmsg/recvmsg");
    if (rc != 0) {
        close(recv_fd);
        return;
    }

    rc = getsockname(
        recv_fd,
        (struct sockaddr *)&recv_addr,
        &recv_addrlen
    );
    TEST_ASSERT(rc == 0, "getsockname() receiver for UDP sendmsg/recvmsg");
    if (rc != 0) {
        close(recv_fd);
        return;
    }

    int send_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(send_fd >= 0, "socket() sender for UDP sendmsg/recvmsg");
    if (send_fd < 0) {
        close(recv_fd);
        return;
    }

    const char *payload = "udp-sendmsg-payload";

    struct iovec send_iov;
    send_iov.iov_base = (void *)payload;
    send_iov.iov_len = strlen(payload);

    struct msghdr send_header;
    memset(&send_header, 0, sizeof(send_header));
    send_header.msg_name = &recv_addr;
    send_header.msg_namelen = sizeof(recv_addr);
    send_header.msg_iov = &send_iov;
    send_header.msg_iovlen = 1;

    ssize_t sent = sendmsg(send_fd, &send_header, 0);

    LOGI(
        "sendmsg(%d, UDP msg_name 127.0.0.1:%d, \"%s\", %zu) -> %zd",
        send_fd,
        ntohs(recv_addr.sin_port),
        payload,
        strlen(payload),
        sent
    );
    TEST_ASSERT(
        sent == (ssize_t)strlen(payload),
        "sendmsg() UDP msg_name returned correct byte count"
    );

    char receive_buffer[64];
    memset(receive_buffer, 0, sizeof(receive_buffer));

    struct iovec receive_iov;
    receive_iov.iov_base = receive_buffer;
    receive_iov.iov_len = sizeof(receive_buffer) - 1;

    struct sockaddr_in source_addr;
    memset(&source_addr, 0, sizeof(source_addr));

    struct msghdr receive_header;
    memset(&receive_header, 0, sizeof(receive_header));
    receive_header.msg_name = &source_addr;
    receive_header.msg_namelen = sizeof(source_addr);
    receive_header.msg_iov = &receive_iov;
    receive_header.msg_iovlen = 1;

    ssize_t received = recvmsg(recv_fd, &receive_header, 0);

    LOGI(
        "recvmsg(%d, UDP msg_name) -> %zd, source=127.0.0.1:%d, data=\"%s\"",
        recv_fd,
        received,
        ntohs(source_addr.sin_port),
        receive_buffer
    );
    TEST_ASSERT(
        received == sent,
        "recvmsg() UDP msg_name returned same byte count as sendmsg()"
    );
    TEST_ASSERT(
        memcmp(receive_buffer, payload, (size_t)received) == 0,
        "recvmsg() UDP msg_name data matches"
    );

    close(send_fd);
    close(recv_fd);
}

/* ------------------------------------------------------------------ */
/* Test 3: close() on a hook-tracked socket                           */
/*                                                                    */
/* sockets.ts hook:                                                   */
/*   close -> "Libc::close"                                           */
/*                                                                    */
/* The hook emits close events for descriptors tracked by the native  */
/* socket() hook. A connected loopback pair ensures endpoint metadata */
/* is available before close().                                       */
/* ------------------------------------------------------------------ */
static void test_close_tracked(void) {
    LOGI("");
    LOGI("=== Native socket tests: close() on tracked socket ===");

    int cli = -1, srv = -1;
    if (make_loopback_pair(&cli, &srv) != 0) {
        TEST_ASSERT(0, "make_loopback_pair for close test");
        return;
    }
    TEST_ASSERT(1, "make_loopback_pair for close test");

    /* Single-byte exchange to confirm fds are active before close */
    const char ping = 0x42;
    ssize_t w = send(cli, &ping, 1, 0);
    TEST_ASSERT(w == 1, "close test: send 1 byte before close");

    char pong = 0;
    ssize_t r = recv(srv, &pong, 1, 0);
    TEST_ASSERT(r == 1 && pong == ping, "close test: recv 1 byte before close");

    /* close() calls — hook target in sockets.ts */
    int rc_cli = close(cli);
    LOGI("close(%d) -> %d", cli, rc_cli);
    TEST_ASSERT(rc_cli == 0, "close() client fd returned 0");

    int rc_srv = close(srv);
    LOGI("close(%d) -> %d", srv, rc_srv);
    TEST_ASSERT(rc_srv == 0, "close() server fd returned 0");
}

/* ------------------------------------------------------------------ */
/* Test 4: sendto() / recvfrom() on a UDP loopback pair                */
/*                                                                     */
/* sockets.ts hooks:                                                   */
/*   sendto   -> socket.native.sendto                                */
/*   recvfrom -> socket.native.recvfrom                                */
/*                                                                     */
/* Uses AF_INET SOCK_DGRAM; no connect() so the explicit destination   */
/* address path in the sendto hook is exercised (this.ipAddr != 0).   */
/* recvfrom is called with a non-null src_addr pointer so the address- */
/* extraction branch in the hook is also reached.                      */
/* ------------------------------------------------------------------ */
static void test_sendto_recvfrom(void) {
    LOGI("");
    LOGI("=== Native socket tests: sendto / recvfrom (UDP) ===");

    /* Receiver: bound UDP socket on loopback, OS-assigned port */
    int recv_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(recv_fd >= 0, "socket() for recvfrom test");
    if (recv_fd < 0) return;

    struct sockaddr_in recv_addr;
    socklen_t addrlen = sizeof(recv_addr);
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family      = AF_INET;
    recv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    recv_addr.sin_port        = 0;

    int rc = bind(recv_fd, (struct sockaddr *)&recv_addr, sizeof(recv_addr));
    TEST_ASSERT(rc == 0, "bind() for recvfrom test");
    if (rc != 0) { close(recv_fd); return; }

    rc = getsockname(recv_fd, (struct sockaddr *)&recv_addr, &addrlen);
    TEST_ASSERT(rc == 0, "getsockname() for recvfrom test");

    /* Sender: unconnected UDP socket - uses explicit destination in sendto() */
    int send_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(send_fd >= 0, "socket() sender for sendto test");
    if (send_fd < 0) { close(recv_fd); return; }

    /* sendto() with explicit destination address - exercises this.ipAddr != 0 branch */
    const char *payload = "sendto-recvfrom-payload";
    ssize_t sent = sendto(send_fd, payload, strlen(payload), 0,
                          (struct sockaddr *)&recv_addr, sizeof(recv_addr));
    LOGI("sendto(%d, \"%s\", %zu, 0, 127.0.0.1:%d) -> %zd",
         send_fd, payload, strlen(payload), ntohs(recv_addr.sin_port), sent);
    TEST_ASSERT(sent == (ssize_t)strlen(payload),
                "sendto() returned correct byte count");

    /* recvfrom() with non-null src_addr - exercises address-extraction branch */
    char buf[64];
    memset(buf, 0, sizeof(buf));
    struct sockaddr_in src_addr;
    socklen_t src_addrlen = sizeof(src_addr);
    ssize_t rcvd = recvfrom(recv_fd, buf, sizeof(buf) - 1, 0,
                            (struct sockaddr *)&src_addr, &src_addrlen);
    LOGI("recvfrom(%d, buf, %zu, 0, &src) -> %zd, data=\"%s\"",
         recv_fd, sizeof(buf) - 1, rcvd, buf);
    TEST_ASSERT(rcvd == sent,
                "recvfrom() returned same byte count as sendto()");
    TEST_ASSERT(memcmp(buf, payload, (size_t)rcvd) == 0,
                "recvfrom() data matches sent payload");

    close(send_fd);
    close(recv_fd);
}

JNIEXPORT jboolean JNICALL
Java_com_test_networke2e_NativeSocketTests_startFilesystemLocalSocketServer(
        JNIEnv *env,
        jclass clazz,
        jstring socket_path
) {
    (void)clazz;

    if (filesystem_local_server_started) {
        LOGE("filesystem LocalSocket server is already active");
        return JNI_FALSE;
    }

    if (socket_path == NULL) {
        LOGE("filesystem LocalSocket server received null path");
        return JNI_FALSE;
    }

    const char *path_chars = (*env)->GetStringUTFChars(
        env,
        socket_path,
        NULL
    );
    if (path_chars == NULL) {
        LOGE("filesystem LocalSocket server failed to read path");
        return JNI_FALSE;
    }

    size_t path_length = strlen(path_chars);

    if (
        path_length == 0 ||
        path_length >= sizeof(filesystem_local_server_path)
    ) {
        LOGE(
            "filesystem LocalSocket path length invalid: %zu",
            path_length
        );
        (*env)->ReleaseStringUTFChars(env, socket_path, path_chars);
        return JNI_FALSE;
    }

    memset(
        filesystem_local_server_path,
        0,
        sizeof(filesystem_local_server_path)
    );
    memcpy(
        filesystem_local_server_path,
        path_chars,
        path_length
    );
    (*env)->ReleaseStringUTFChars(env, socket_path, path_chars);

    int listener_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener_fd < 0) {
        LOGE(
            "filesystem LocalSocket server socket() failed, errno=%d",
            errno
        );
        return JNI_FALSE;
    }

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, filesystem_local_server_path, path_length);

    unlink(filesystem_local_server_path);

    if (
        bind(
            listener_fd,
            (struct sockaddr *)&address,
            sizeof(address)
        ) < 0
    ) {
        LOGE(
            "filesystem LocalSocket server bind() failed, errno=%d",
            errno
        );
        close(listener_fd);
        unlink(filesystem_local_server_path);
        return JNI_FALSE;
    }

    if (listen(listener_fd, 1) < 0) {
        LOGE(
            "filesystem LocalSocket server listen() failed, errno=%d",
            errno
        );
        close(listener_fd);
        unlink(filesystem_local_server_path);
        return JNI_FALSE;
    }

    filesystem_local_server_listener = listener_fd;
    filesystem_local_server_result = -1;
    filesystem_local_server_started = 1;

    int thread_result = pthread_create(
        &filesystem_local_server_thread,
        NULL,
        filesystem_local_server_main,
        NULL
    );

    if (thread_result != 0) {
        LOGE(
            "filesystem LocalSocket server pthread_create() failed, result=%d",
            thread_result
        );
        close(filesystem_local_server_listener);
        filesystem_local_server_listener = -1;
        unlink(filesystem_local_server_path);
        filesystem_local_server_started = 0;
        return JNI_FALSE;
    }

    LOGI(
        "filesystem LocalSocket server listening at %s",
        filesystem_local_server_path
    );

    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_com_test_networke2e_NativeSocketTests_waitForFilesystemLocalSocketServer(
        JNIEnv *env,
        jclass clazz
) {
    (void)env;
    (void)clazz;

    if (!filesystem_local_server_started) {
        LOGE("filesystem LocalSocket server was not started");
        return JNI_FALSE;
    }

    int join_result = pthread_join(
        filesystem_local_server_thread,
        NULL
    );

    filesystem_local_server_started = 0;

    if (join_result != 0) {
        LOGE(
            "filesystem LocalSocket server pthread_join() failed, result=%d",
            join_result
        );
        return JNI_FALSE;
    }

    return filesystem_local_server_result == 0
        ? JNI_TRUE
        : JNI_FALSE;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                          */
/* ------------------------------------------------------------------ */
JNIEXPORT void JNICALL
Java_com_test_networke2e_NativeSocketTests_runTests(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    tests_passed = 0;
    tests_failed = 0;

    LOGI("========================================");
    LOGI("NativeSocketTests: starting");
    LOGI("========================================");

    LOGI("");
    LOGI(">> Running test_socket_created_only...");
    test_socket_created_only();

    LOGI("");
    LOGI(">> Running test_send_recv...");
    test_send_recv();

    LOGI("");
    LOGI(">> Running test_dlsym_send_recv...");
    test_dlsym_send_recv();

    LOGI("");
    LOGI(">> Running test_sendmsg_recvmsg...");
    test_sendmsg_recvmsg();

    LOGI("");
    LOGI(">> Running test_sendmsg_recvmsg_udp...");
    test_sendmsg_recvmsg_udp();

    LOGI("");
    LOGI(">> Running test_close_tracked...");
    test_close_tracked();

    LOGI("");
    LOGI(">> Running test_sendto_recvfrom...");
    test_sendto_recvfrom();

    LOGI("========================================");
    LOGI("NativeSocketTests summary: %d passed, %d failed",
         tests_passed, tests_failed);
    LOGI("========================================");
}