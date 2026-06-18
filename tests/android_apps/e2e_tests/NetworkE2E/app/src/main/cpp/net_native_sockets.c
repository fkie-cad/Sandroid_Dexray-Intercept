#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <jni.h>
#include <android/log.h>

#define LOG_TAG "NET_NATIVE_SOCKETS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * Exercises libc socket syscalls hooked in sockets.ts via safeAttachExport:
 *
 *   send()     → "Libc::send"
 *   recv()     → "Libc::recv"
 *   sendmsg()  → "Libc::sendmsg"
 *   recvmsg()  → "Libc::recvmsg"
 *   close()    → "Libc::close"
 *
 * Each test creates a loopback TCP pair in a single thread:
 *   listen() with backlog ≥ 1 → connect() (kernel buffers it) → accept()
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

/* ------------------------------------------------------------------ */
/* Helper: create a connected loopback TCP pair in one thread.         */
/*   *cli_fd  → connected client side                                  */
/*   *srv_fd  → accepted server side                                   */
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

/* ------------------------------------------------------------------ */
/* Test 1: send() / recv()                                             */
/*                                                                     */
/* sockets.ts hooks:                                                   */
/*   send  → "Libc::send"                                              */
/*   recv  → "Libc::recv"                                              */
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

    /* send() from client → server */
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

    /* send() from server → client (reverse direction) */
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
/* Test 2: sendmsg() / recvmsg()                                       */
/*                                                                     */
/* sockets.ts hooks:                                                   */
/*   sendmsg → "Libc::sendmsg"                                         */
/*   recvmsg → "Libc::recvmsg"                                         */
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

    /* Reverse direction: sendmsg server → client */
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
/* Test 3: close() on a hook-tracked socket                            */
/*                                                                     */
/* sockets.ts hook:                                                    */
/*   close → "Libc::close"                                             */
/*                                                                     */
/* The hook only emits for file descriptors present in socket_list,    */
/* i.e. those that previously passed through the native connect or     */
/* bind hooks.  A connected loopback pair is therefore used so both    */
/* fds are candidates for tracking.  A single-byte exchange is         */
/* performed before close() to ensure the connect hook path was        */
/* reached first.                                                       */
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
    LOGI(">> Running test_send_recv...");
    test_send_recv();

    LOGI("");
    LOGI(">> Running test_sendmsg_recvmsg...");
    test_sendmsg_recvmsg();

    LOGI("");
    LOGI(">> Running test_close_tracked...");
    test_close_tracked();

    LOGI("========================================");
    LOGI("NativeSocketTests summary: %d passed, %d failed",
         tests_passed, tests_failed);
    LOGI("========================================");
}