
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#define BUF_SIZE 4096
#define SOCKS_PORT 1080

void *tcp_handler(void *arg);
void *udp_relay_thread(void *arg);

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
} udp_ctx_t;

int main() {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SOCKS_PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(listen_fd, 5);

    printf("SOCKS5 server (TCP+UDP) listening on %d\n", SOCKS_PORT);

    while (1) {
        int client_fd = accept(listen_fd, NULL, NULL);
        int *pfd = malloc(sizeof(int));
        //printf("client_id=%d\n",client_fd);
        *pfd = client_fd;
        pthread_t tid;
        pthread_create(&tid, NULL, tcp_handler, pfd);
        pthread_detach(tid);
    }
    return 0;
}
void printbuf(unsigned char buf[BUF_SIZE]){
    for (int i = 0; i < BUF_SIZE; i++) {
        printf("%02x ", buf[i]); // %02x 表示两位十六进制，不足补零
        if ((i + 1) % 16 == 0) printf("\n"); // 每16个字节换行
    }
}
void *tcp_handler(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);
    unsigned char buf[BUF_SIZE];
    int sign =recv(client_fd, buf, 2, 0);
    //printf("sign=%d,Buff0=%d\n",sign,buf[0]);
    // greeting
    if (sign!=2 || buf[0] != 0x05) {
        close(client_fd);
        return NULL;
    }
    int nmethods = buf[1];
    recv(client_fd, buf, nmethods, 0);
    unsigned char reply[2] = {0x05, 0x00};
    send(client_fd, reply, 2, 0);

    // request
    recv(client_fd, buf, BUF_SIZE, 0);
    //printf("sign=%d\n",sign,buf[0]);
    //if (sign != 4) {
    //    close(client_fd);
    //    return NULL;
    //}
    
    int cmd = buf[1], atyp = buf[3];
    if (cmd == 0x03) { // UDP ASSOCIATE
        
        //recv(client_fd, buf, BUF_SIZE, 0); // IPv4 + port
        //printbuf(buf);
        // bind udp relay socket
        int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in relay_addr = {
            .sin_family = AF_INET,
            .sin_port = 0,
            .sin_addr.s_addr = INADDR_ANY
        };


        bind(udp_fd, (struct sockaddr *)&relay_addr, sizeof(relay_addr));
        socklen_t len = sizeof(relay_addr);
        getsockname(udp_fd, (struct sockaddr *)&relay_addr, &len);

        // respond to client
        unsigned char rep[10] = {0x05, 0x00, 0x00, 0x01};
        memcpy(rep + 4, &relay_addr.sin_addr, 4);
        rep[8] = relay_addr.sin_port >> 8;
        rep[9] = relay_addr.sin_port & 0xff;
        

        // start relay thread
        udp_ctx_t *ctx = malloc(sizeof(udp_ctx_t));
        ctx->client_fd = udp_fd;
        pthread_t tid;
        printf("start work in = %d udp_fd=%d\n",ctx,udp_fd);
        pthread_create(&tid, NULL, udp_relay_thread, ctx);
        pthread_detach(tid);

        send(client_fd, rep, 10, 0);
        sleep(100000);
        // keep TCP alive (until closed)
        recv(client_fd, buf, 1, 0);
        close(client_fd);
        //
        printf("stop work in = %d\n",ctx);
        return NULL;
    } else if (cmd == 0x01) {
        // CONNECT (TCP relay, IPv4 only)
        
        sign=recv(client_fd, buf, BUF_SIZE, 0);
        printf("atyp=%dsign=%d\n",atyp,sign);
        if (sign< 6) {
            close(client_fd);
            return NULL;
        }
        char ip[INET_ADDRSTRLEN];
        uint16_t port = 0;
        if (atyp == 0x01){
        
            inet_ntop(AF_INET, buf, ip, sizeof(ip));
            port = (buf[4] << 8) | buf[5];
        }
        else if(atyp == 0x03){

            uint8_t domain_len = buf[0]; // 第 1 字节表示域名长度
            char domain[256] = {0};
            memcpy(domain, buf + 1, domain_len);
            domain[domain_len] = '\0';

            port = (buf[1 + domain_len] << 8) | buf[2 + domain_len];

            // 解析域名（需要 DNS 解析）
            struct hostent *he = gethostbyname(domain);
            if (he == NULL) {
                fprintf(stderr, "DNS resolution failed for %s\n", domain);
                close(client_fd);
                return NULL;
            }

            inet_ntop(AF_INET, he->h_addr, ip, sizeof(ip));
        }



        int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in remote_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(port)
        };
        inet_pton(AF_INET, ip, &remote_addr.sin_addr);

        if (connect(remote_fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0) {
            close(client_fd); close(remote_fd); return NULL;
        }

        unsigned char rep[10] = {0x05, 0x00, 0x00, 0x01};
        memcpy(rep + 4, &remote_addr.sin_addr, 4);
        rep[8] = port >> 8; rep[9] = port & 0xff;
        send(client_fd, rep, 10, 0);

        fd_set fds;
        while (1) {
            FD_ZERO(&fds);
            FD_SET(client_fd, &fds);
            FD_SET(remote_fd, &fds);
            int maxfd = client_fd > remote_fd ? client_fd : remote_fd;
            if (select(maxfd + 1, &fds, NULL, NULL, NULL) <= 0) break;

            if (FD_ISSET(client_fd, &fds)) {
                int len = recv(client_fd, buf, BUF_SIZE, 0);
                if (len <= 0) break;
                send(remote_fd, buf, len, 0);
            }
            if (FD_ISSET(remote_fd, &fds)) {
                int len = recv(remote_fd, buf, BUF_SIZE, 0);
                if (len <= 0) break;
                send(client_fd, buf, len, 0);
            }
        }
        close(client_fd); close(remote_fd);
        return NULL;
    } else {
        close(client_fd);
        return NULL;
    }
}

void *udp_relay_thread(void *arg) {
    udp_ctx_t *ctx = (udp_ctx_t *)arg;
    int udp_fd = ctx->client_fd;
    free(ctx);
    printf("udpFD=%d\n",udp_fd);
    unsigned char buf[BUF_SIZE];

    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    while (1) {
        printf("start listen\n");
        int len = recvfrom(udp_fd, buf, BUF_SIZE, 0,
                           (struct sockaddr *)&client_addr, &addrlen);
        printf("lenth=%d\n",len);
        if (len <= 10) continue;
        
        // parse socks5 UDP header
        int frag = buf[2];
        printf("frag=%d\n",frag);
        if (frag != 0) continue; // ignore fragmented

        int atyp = buf[3];
        char dst_ip[INET_ADDRSTRLEN];
        uint16_t dst_port;
        printf("atyp=%d\n",atyp);
        if (atyp == 0x01) {
            memcpy(dst_ip, &buf[4], 4);
            dst_port = (buf[8] << 8) | buf[9];

            struct sockaddr_in target_addr = {
                .sin_family = AF_INET,
                .sin_port = htons(dst_port)
            };
            memcpy(&target_addr.sin_addr, &buf[4], 4);

            int payload_offset = 10;
            int payload_len = len - payload_offset;

            sendto(udp_fd, buf + payload_offset, payload_len, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr));
        }
    }
    close(udp_fd);
    return NULL;
}
