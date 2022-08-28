// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


#define _XOPEN_SOURCE 700
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ev.h>
#include <uthash.h>

#include <dtp_config.h>
#include <quiche.h>
#include <openssl/aes.h>

#define AES_BITS 32*8
#define MSG_LEN 1280

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

#define MAX_BLOCK_SIZE 1000000  // 1Mbytes

int aesFlag=1;
AES_KEY  aaeeskey; 
char * key =NULL;
char *dtp_cfg_fname;
int cfgs_len;
struct dtp_config *cfgs = NULL;
bool has_send_len = false;
uint8_t * keyBuf=NULL;
int encFlag=0;
uint64_t start_timestamp = 0;
uint64_t end_timestamp = 0;

uint64_t send_bytes = 0;
uint64_t complete_bytes = 0;
uint64_t good_bytes = 0;

#define MAX_TOKEN_LEN                                        \
    sizeof("quiche") - 1 + sizeof(struct sockaddr_storage) + \
        QUICHE_MAX_CONN_ID_LEN

int open_times = 0;
const char* WRITE_TO_FILENAME = "./log/server_aitrans.log";
// Use fprintf and open a single file to write texts
// Usage of this macro is the same with that of printf
// The first time you use this macro will replace the entire file, the following callings only append the file
// You can edit WRITE_TO_FILENAME variable to change the file to write
#define WRITE_TO_FILE(...) \
{\
    FILE* clientlog = open_times == 0 ? fopen(WRITE_TO_FILENAME, "w") : fopen(WRITE_TO_FILENAME, "a+"); \
    if(clientlog == NULL) { \
        perror("cannot open WRITE_TO_FILENAME file");\
    }   \
    open_times ++; \
    fprintf(clientlog, __VA_ARGS__); \
    fclose(clientlog); \
}
struct connections {
    int sock;

    struct conn_io *h;
};

struct conn_io {
    ev_timer timer;
    ev_timer sender;
    int send_round;
    int configs_len;
    dtp_config *configs;

    int sock;

    uint64_t t_last;
    ssize_t can_send;
    bool done_writing;
    ev_timer pace_timer;

    uint8_t cid[LOCAL_CONN_ID_LEN];

    quiche_conn *conn;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    UT_hash_handle hh;
};

static quiche_config *config = NULL;

static struct connections *conns = NULL;

static void timeout_cb(EV_P_ ev_timer *w, int revents);

// static void debug_log(const char *line, void *argp) {
//     fprintf(stderr, "%s\n", line);
// }
//project 4,register and get the key
//{"code":200,"msg":"成功","result":"####"}


char * getSend(const char *,const char *,const char *);
int32_t aes_encrypt(uint8_t* in,  char* key, uint8_t* out,int len); // 加密
int32_t aes_decrypt(uint8_t* in,  char* key, uint8_t* out,int len); // 解密

 
int32_t 
cfbDE(uint8_t* in,  char* key, uint8_t* out,int len)
{
    
  
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    
    
   // int num=16;
   len +=16;
   len-=len%16;
   int num=0;

    AES_cfb128_encrypt(in,out,len,&aaeeskey, iv, &num,0);
    return 0;
}
 
 
int32_t 
cfbEN(uint8_t* in,  char* key, uint8_t* out,int len)
{   
     
   
    unsigned char iv[AES_BLOCK_SIZE] = {0};
   
    int num=0;
       len +=16;
   len-=len%16;
    AES_cfb128_encrypt(in,out,len, &aaeeskey, iv, &num,1);
 
    return 0;
}
 void pri(char * str,int len,char bro[]){
     printf("%s\n",bro);
     
     for(int i=0;i<len;i++)
        printf("%d ",str[i]);

    printf("\n");
 }
void aes_init(AES_KEY * aesKey,char * srcKey){
    AES_set_encrypt_key((uint8_t*)srcKey, 128, aesKey);
}
void preCFB(uint8_t in[],int lenIn,uint8_t out[],int lenOut,int flag ){
    
    memset( out, '\0',lenOut );
   
  //  printf("调用函数  1 :%s\n",func);
     
    if(flag ==1){
        
        cfbEN(in,key,out,lenIn);
       // printf("server:input:%ld,encoded,len %ld\n",strlen((char *)in),strlen((char *)out));//strlen returns the length of a string ended with '\0'
    }
    else{
        cfbDE(in,key,out,lenIn);
       // printf("server:input:%ld,decoded,len %ld\n",strlen((char *)in),strlen((char *)out));
    }

    return ;
}
void preProcessBuf(uint8_t in[],int lenIn,uint8_t out[],int lenOut,int flag,char func[]);

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    // fprintf(stderr, "enter flush\n");
    static uint8_t out[MAX_DATAGRAM_SIZE];
   // static uint8_t cypher[MAX_DATAGRAM_SIZE+16];
    uint64_t rate = quiche_bbr_get_pacing_rate(conn_io->conn);  // bits/s
    /* WRITE_TO_FILE("%lu pacing: %lu\n", getCurrentUsec(), rate); */
    if (conn_io->done_writing) {
        conn_io->can_send = MAX_DATAGRAM_SIZE+16;
        conn_io->t_last = getCurrentUsec();
        conn_io->done_writing = false;
    }

    while (1) {
        uint64_t t_now = getCurrentUsec();
        conn_io->can_send += rate * (t_now - conn_io->t_last) /
                             8000000;  //(bits/8)/s * s = bytes
        // fprintf(stderr, "%ld us time went, %ld bytes can send\n",
        //         t_now - conn_io->t_last, conn_io->can_send);
        conn_io->t_last = t_now;
        if (conn_io->can_send < MAX_DATAGRAM_SIZE+16) {
            // fprintf(stderr, "can_send < 1350\n");
            conn_io->pace_timer.repeat = 0.001;
            ev_timer_again(loop, &conn_io->pace_timer);
            break;
        }
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out));

        if (written == QUICHE_ERR_DONE) {
            // fprintf(stderr, "done writing\n");
            conn_io->done_writing = true;  // app_limited
            conn_io->pace_timer.repeat = 99999.0;
            ev_timer_again(loop, &conn_io->pace_timer);
            break;
        }

        if (written < 0) {
            // fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }
        size_t  sent;
        sent = sendto(conn_io->sock, out, written, 0,
                              (struct sockaddr *)&conn_io->peer_addr,conn_io->peer_addr_len);
    
                   
        if (sent != written  ) {
            perror("failed to send\n");
          //  return;
        }

        send_bytes += sent;
        // fprintf(stderr, "sent %zd bytes\n", sent);
        conn_io->can_send -= sent;
    }


    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    // timer.repeat can't be 0.0
    if (t <= 0.00000001) {
        t = 0.001;
    }
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
}

static void flush_egress_pace(EV_P_ ev_timer *pace_timer, int revents) {
    struct conn_io *conn_io = pace_timer->data;
    // fprintf(stderr, "begin flush_egress_pace\n");
    flush_egress(loop, conn_io);
}

static void mint_token(const uint8_t *dcid, size_t dcid_len,
                       struct sockaddr_storage *addr, socklen_t addr_len,
                       uint8_t *token, size_t *token_len) {
    memcpy(token, "quiche", sizeof("quiche") - 1);
    memcpy(token + sizeof("quiche") - 1, addr, addr_len);
    memcpy(token + sizeof("quiche") - 1 + addr_len, dcid, dcid_len);

    *token_len = sizeof("quiche") - 1 + addr_len + dcid_len;
}

static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len) {
    if ((token_len < sizeof("quiche") - 1) ||
        memcmp(token, "quiche", sizeof("quiche") - 1)) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        return false;
    }

    memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}

static void sender_cb(EV_P_ ev_timer *w, int revents) {
    // fprintf(stderr,"enter sender cb\n");
    struct conn_io *conn_io = w->data;

    if (quiche_conn_is_established(conn_io->conn)) {
        int deadline = 0;
        int priority = 0;
        int block_size = 0;
        int depend_id = 0;
        int stream_id = 0;
        float send_time_gap = 0.0;
        static uint8_t buf[MAX_BLOCK_SIZE];
        static uint8_t encBuf[100010];
        FILE *fp =fopen(dtp_cfg_fname,"r");
 
      if(fp == NULL) 
      {
          perror("打开文件时发生错误");
         return ;
     }
     printf("加密前交易信息\n");
     int i=0;
     for(i=0;i<MAX_BLOCK_SIZE&&!feof(fp);i++){
         buf[i]=fgetc(fp);
     }
     
     buf[i-1]=0;
     i--;
     printf("%s\n",buf);
      
    memcpy(encBuf,buf,i+1);
    if(aesFlag ==1){
        preCFB(buf,i,encBuf,100010,1);
    }

    printf("加密后交易信息:\n");
    printf("%s\n\n",encBuf);
    encFlag=2;

 
    static uint8_t sndb[100];

    conn_io->configs[0].block_size=strlen((char *)encBuf);
    block_size=conn_io->configs[0].block_size;
   
     
    conn_io->configs[0].deadline=10000;
    conn_io->configs[0].priority=1;
    conn_io->configs[0].send_time_gap=0.000001;

    

    if (!has_send_len) {
     *((int*)sndb) = cfgs_len;
      if (quiche_conn_stream_send_full(conn_io->conn, 1, sndb, 4, true, 100000, 0, 0) < 0) {
           WRITE_TO_FILE("failed to send cfgs number\n");
         } else {
          has_send_len = true;
         }
      }

        for (int i = conn_io->send_round; i < conn_io->configs_len; i++) {
            send_time_gap = conn_io->configs[i].send_time_gap;  // sec
            deadline = conn_io->configs[i].deadline;
            priority = conn_io->configs[i].priority;
            block_size = conn_io->configs[i].block_size;
            stream_id = 4 * (conn_io->send_round + 1) + 1;
      
            depend_id = stream_id;
            if (block_size > MAX_BLOCK_SIZE) block_size = MAX_BLOCK_SIZE;

            if (quiche_conn_stream_send_full(conn_io->conn, stream_id, encBuf,
                                             block_size, true, deadline,
                                             priority, depend_id) < 0) {
                
            } else {
                 
            }

            conn_io->send_round++;
            if (conn_io->send_round >= conn_io->configs_len) {
                ev_timer_stop(loop, &conn_io->sender);
                // uint8_t reason[] = "done writing";
                // quiche_conn_close(conn_io->conn, false, QUICHE_ERR_DONE, reason, sizeof(reason));
                break;
            }

            if (send_time_gap > 0.005) {
                conn_io->sender.repeat = send_time_gap;
                ev_timer_again(loop, &conn_io->sender);
                // fprintf(stderr, "time gap: %f\n", send_time_gap);
                break;  //每次只发一个block
            } else {
                continue;  //如果间隔太小，则接着发
            }
        }
    }
    flush_egress(loop, conn_io);
}

static struct conn_io *create_conn(struct ev_loop *loop, uint8_t *odcid,
                                   size_t odcid_len) {
    // fprintf(stderr,"enter create_conn\n");
    struct conn_io *conn_io = malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return NULL;
    }

    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return NULL;
    }

    ssize_t rand_len = read(rng, conn_io->cid, LOCAL_CONN_ID_LEN); //lyx ?? note the fd is a file 
   
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return NULL;
    }

    quiche_conn *conn = quiche_accept(conn_io->cid, LOCAL_CONN_ID_LEN, odcid,
                                      odcid_len, config);
    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return NULL;
    }

    conn_io->sock = conns->sock;
    conn_io->conn = conn;

    conn_io->send_round = -1;

    cfgs = parse_dtp_config(dtp_cfg_fname, &cfgs_len);
   cfgs_len=1;
        conn_io->configs_len = cfgs_len;
        conn_io->configs = malloc(sizeof(*cfgs) * cfgs_len);;
    
   
  

    conn_io->t_last = getCurrentUsec();
    conn_io->can_send = MAX_DATAGRAM_SIZE+16;
    conn_io->done_writing = false;

    // quiche_conn_set_tail(conn, 5000);

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    ev_init(&conn_io->sender, sender_cb);
    conn_io->sender.data = conn_io;

    ev_init(&conn_io->pace_timer, flush_egress_pace);
    conn_io->pace_timer.data = conn_io;

    HASH_ADD(hh, conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);

    start_timestamp = getCurrentUsec();
    fprintf(stderr, "new connection,  timestamp: %lu\n",
            start_timestamp);

    return conn_io;
}

static void release_conn_io(struct ev_loop * loop, struct conn_io* conn_io) {
    ev_timer_stop(loop, &conn_io->timer);
    ev_timer_stop(loop, &conn_io->sender);
    ev_timer_stop(loop, &conn_io->pace_timer);
    quiche_conn_free(conn_io->conn);
    free(conn_io->configs);
    free(conn_io);
}

static void recv_cb(EV_P_ ev_io *w, int revents) {
    // fprintf(stderr,"enter recv\n");
    struct conn_io *tmp, *conn_io = NULL;

    static uint8_t buf[MAX_BLOCK_SIZE];
  //  static uint8_t encode_data[MAX_BLOCK_SIZE];

    static uint8_t out[MAX_DATAGRAM_SIZE];
  //  static uint8_t cypher[MAX_DATAGRAM_SIZE+16];
    

    uint8_t i = 3;

    while (i--) {
        // printf("try %d\n", i);

        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read;
         read = recvfrom(conns->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *)&peer_addr, &peer_addr_len);
            
   // WRITE_TO_FILE("\nthe read is :%ld\n",read);
       // aes_decrypt(encode_data, key,buf );

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                // fprintf(stderr, "recv would block\n");
                break;
            }

            perror("server failed to read");
            return;
        }

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            fprintf(stderr, "failed to parse header: %d\n", rc);
            return;
        }

        HASH_FIND(hh, conns->h, dcid, dcid_len, conn_io);

        if (conn_io == NULL) {
            if (!quiche_version_is_supported(version)) {
                // fprintf(stderr, "version negotiation\n");

                ssize_t written = quiche_negotiate_version(
                    scid, scid_len, dcid, dcid_len, out, sizeof(out));

                if (written < 0) {
                    // fprintf(stderr, "failed to create vneg packet: %zd\n",
                    // written);
                    return;
                }
                //aes_encrypt(out, key, cypher);
                ssize_t sent;
                sent =sendto(conns->sock, out, written, 0,
                           (struct sockaddr *)&peer_addr, peer_addr_len);
                    
     
                if (sent != written) {
                      perror("failed to send");
               //     return;
                }

                send_bytes += sent;
             
                return;
            }

            if (token_len == 0) {
                mint_token(dcid, dcid_len, &peer_addr, peer_addr_len, token,
                           &token_len);

                ssize_t written =
                    quiche_retry(scid, scid_len, dcid, dcid_len, dcid, dcid_len,
                                 token, token_len, out, sizeof(out));

                if (written < 0) {
                    // fprintf(stderr, "failed to create retry packet: %zd\n",
                    //         written);
                    return;
                }
                //aes_encrypt(out, key, cypher);
                ssize_t sent;
                sent =sendto(conns->sock, out, written, 0,
                           (struct sockaddr *)&peer_addr, peer_addr_len);
             
                if (sent != written) {
                     perror("failed to send");
                 //   return;
                }

                send_bytes += sent;
                // fprintf(stderr, "sent %zd bytes\n", sent);
                return;
            }

            if (!validate_token(token, token_len, &peer_addr, peer_addr_len,
                                odcid, &odcid_len)) {
                // fprintf(stderr, "invalid address validation token\n");
                return;
            }

            conn_io = create_conn(loop, odcid, odcid_len);
            if (conn_io == NULL) {
                return;
            }

            memcpy(&conn_io->peer_addr, &peer_addr, peer_addr_len);
            conn_io->peer_addr_len = peer_addr_len;
        }
        
        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read);
        
        if (done == QUICHE_ERR_DONE) {
            // fprintf(stderr, "done reading\n");
            break;
        }

        if (done < 0) {
            // fprintf(stderr, "failed to process packet: %zd\n", done);
            return;
        }

        // fprintf(stderr, "recv %zd bytes\n", done);

        if (quiche_conn_is_established(conn_io->conn)) {
            // begin send data: block trace
            // start sending first block immediately.
            if (conn_io->send_round == -1) {
                conn_io->send_round = 0;
                conn_io->sender.repeat = cfgs[0].send_time_gap > 0.0001
                                             ? cfgs[0].send_time_gap
                                             : 0.0001;
                ev_timer_again(loop, &conn_io->sender);
            }

            uint64_t s = 0;

            quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

            while (quiche_stream_iter_next(readable, &s)) {
                // fprintf(stderr, "stream %" PRIu64 " is readable\n", s);

                bool fin = false;
                ssize_t recv_len = quiche_conn_stream_recv(
                    conn_io->conn, s, buf, sizeof(buf), &fin);
                if (recv_len < 0) {
                    break;
                }
            }

            quiche_stream_iter_free(readable);
        }
    }

    HASH_ITER(hh, conns->h, conn_io, tmp) {
        flush_egress(loop, conn_io);

        if (quiche_conn_is_closed(conn_io->conn)) {
            // fprintf(stderr, "connection closed in recv_cb\n");
            WRITE_TO_FILE("connection closed in recv_cb\n");
            quiche_stats stats;

            quiche_conn_stats(conn_io->conn, &stats);

            end_timestamp = getCurrentUsec();

            // fprintf(stderr,
            //         "connection closed, you can see result in client.log\n");
            // fprintf(stderr,
            //         "%li: connection closed, recv=%zu sent=%zu lost=%zu rtt=%"
            //         PRIu64 "ns cwnd=%zu\n", end_timestamp, stats.recv, stats.sent,
            //         stats.lost, stats.rtt, stats.cwnd);

            // fprintf(stderr, "total_bytes=%lu, total_time(us)=%lu, throughput(B/s)=%lu\n",
            //     send_bytes, end_timestamp - start_timestamp, send_bytes / ((end_timestamp - start_timestamp) / 1000/ 1000));
            WRITE_TO_FILE("connection closed, you can see result in client.log\n");
            WRITE_TO_FILE("%li: connection closed\nrecv,sent,lost,rtt(ns),cwnd\n%zu,%zu,%zu,%lu,%zu\n",
                end_timestamp, stats.recv, stats.sent, stats.lost, stats.rtt, stats.cwnd);
            WRITE_TO_FILE("total_bytes,total_time(us),throughput(B/s)\n%lu,%lu,%lu\n",
                send_bytes, end_timestamp - start_timestamp, send_bytes / ((end_timestamp - start_timestamp) / 1000/ 1000));

            HASH_DELETE(hh, conns->h, conn_io);

            release_conn_io(loop, conn_io);
            // ev_timer_stop(loop, &conn_io->timer);
            // ev_timer_stop(loop, &conn_io->sender);
            // ev_timer_stop(loop, &conn_io->pace_timer);
            // quiche_conn_free(conn_io->conn);
            // free(conn_io);
        }
    }
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    // fprintf(stderr, "enter timeout\n");
    struct conn_io *conn_io = w->data;
    quiche_conn_on_timeout(conn_io->conn);

    // fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        fprintf(stderr, "connection closed in timeout_cb\n");
        quiche_stats stats;

        quiche_conn_stats(conn_io->conn, &stats);

        end_timestamp = getCurrentUsec();
        // fprintf(stderr,
        //         "%li: connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64
        //         "ns cwnd=%zu\n",
        //         end_timestamp, stats.recv, stats.sent, stats.lost, stats.rtt, stats.cwnd);
        // fprintf(stderr,
        //         "connection closed, you can see result in client.log\n");


        // fprintf(stderr, "total_bytes=%lu, total_time(us)=%lu, throughput(B/s)=%lu\n",
        //     send_bytes, end_timestamp - start_timestamp, send_bytes / ((end_timestamp - start_timestamp) / 1000/ 1000));

        // fflush(stdout);

        WRITE_TO_FILE("connection closed, you can see result in client.log\n");
        WRITE_TO_FILE("%li: connection closed\nrecv,sent,lost,rtt(ns),cwnd\n%zu,%zu,%zu,%lu,%zu\n",
            end_timestamp, stats.recv, stats.sent, stats.lost, stats.rtt, stats.cwnd);
        WRITE_TO_FILE("total_bytes,total_time(us),throughput(B/s)\n%lu,%lu,%lu\n",
            send_bytes, end_timestamp - start_timestamp, send_bytes / ((end_timestamp - start_timestamp) / 1000/ 1000));

        HASH_DELETE(hh, conns->h, conn_io);

        release_conn_io(loop, conn_io);
        // ev_timer_stop(loop, &conn_io->timer);
        // ev_timer_stop(loop, &conn_io->sender);
        // ev_timer_stop(loop, &conn_io->pace_timer);
        // quiche_conn_free(conn_io->conn);
        // free(conn_io);

        return;
    }
}

int main(int argc, char *argv[]) {

    const char * proxyaddr=argv[3];
    const char * srcip=argv[4];
    const char * dstip=argv[5];
    
    char * buf=getSend(srcip,dstip,proxyaddr);
    //char * buf=getSend(srcip,dstip,proxyaddr);
   key=strstr(buf,"result");

  
   unsigned int contLen= strlen (key);
 
    key[contLen-1]='\0';
    key[contLen-2]='\0';
    key+=9;
    
    WRITE_TO_FILE("\nthe key is :%s\n",key);
    if(!strcmp("null",key)){
        printf("\n错误:获取密钥失败\n是否继续进行明文传输?(y or n)\n");
        aesFlag=0;
        char ch=0;
        for(;scanf("%c",&ch)&&ch!='y'&&ch!='n';){
             
        }
        if(ch=='n')
            return 0;
    }else{
        printf("\nThe key is :%s\n", key );
        aes_init(&aaeeskey,key);
    }
    

    
    fprintf(stderr, "server start,  timestamp: %lu\n",
            getCurrentUsec());
    WRITE_TO_FILE("server start,  timestamp: %lu\n",
            getCurrentUsec());
    const char *host = argv[1];
    const char *port = argv[2];
    dtp_cfg_fname = argv[6];
    

    const struct addrinfo hints = {.ai_family = PF_UNSPEC,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};

    // quiche_enable_debug_logging(debug_log, NULL);

    struct addrinfo *local;
    if (getaddrinfo(host, port, &hints, &local) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    int sock = socket(local->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    if (bind(sock, local->ai_addr, local->ai_addrlen) < 0) {
        perror("failed to connect socket");
        return -1;
    }

    config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (config == NULL) {
        // fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_load_cert_chain_from_pem_file(config, "cert.crt");
    quiche_config_load_priv_key_from_pem_file(config, "cert.key");

    quiche_config_set_application_protos(
        config, (uint8_t *)"\x05hq-25\x05hq-24\x05hq-23\x08http/0.9", 21);

    quiche_config_set_max_idle_timeout(config, 3000);
    quiche_config_set_max_packet_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000000);
    quiche_config_set_initial_max_streams_bidi(config, 10000);
    quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);
    quiche_config_set_scheduler_name(config, "dyn");
    // ACK ratio
    /* quiche_config_set_data_ack_ratio(config, 4); */

    struct connections c;
    c.sock = sock;
    c.h = NULL;

    conns = &c;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher, recv_cb, sock, EV_READ);
    ev_io_start(loop, &watcher);
    watcher.data = &c;

    ev_loop(loop, 0);

    freeaddrinfo(local);

    quiche_config_free(config);

    close(sock);

    free(buf);
    return 0;
}
char * getSend(const  char * srcip,const char * dstip,const char * proxyaddr){
    const int BUFLEN=1024;
    FILE   *stream;  
    //FILE    *wstream;
    char * buf=(char *)malloc(BUFLEN*sizeof(char));
    
    memset( buf, '\0',BUFLEN );//初始化buf
    char * registerRequest=(char *)malloc(sizeof(char)*512);
    //char * port="8888";
    sprintf(registerRequest,"curl http://%s/test/register?ip=%s",proxyaddr,srcip);
  //  printf("%s",registerRequest);
    stream = popen(registerRequest , "r" );
    free(registerRequest);
    //将“curl ”命令的输出 通过管道读取（“r”参数）到FILE* stream
   if (fread( buf, sizeof(char), BUFLEN,  stream) ==0){
       return NULL;
   }  
   
   char post_template[]=" curl -X POST -d '{\"srcip\":\"%s\",\"dstip\":\"%s\",\"data\":\"[%s]\"}'   http://%s/test/getKey  --header \"Content-Type: application/json\"";

   char * cont=strstr(buf,"{\\\"hash");
   
   unsigned int contLen= strlen (cont);
 
   cont[contLen-1]='\0';
  cont[contLen-2]='\0';
 
 // char srcip[]="127.0.0.1";
 // char dstip[]="127.0.0.1";

 char request[BUFLEN];

  snprintf(request, BUFLEN, post_template, srcip,dstip,cont,proxyaddr);
  printf("%s",request);
  // printf("%s",request);
   // free(buf);
   // clearerr(stream);
   // printf("\n\n\n\n%s\n",buf);
    //buf=(char *)malloc(BUFLEN*sizeof(char));
    stream = popen(request , "r" );
    //将“curl ”命令的输出 通过管道读取（“r”参数）到FILE* stream
    
    memset( buf, '\0',BUFLEN );//初始化buf

   if (fread( buf, sizeof(char), BUFLEN,  stream) !=0){
        //printf("%s\n",buf);
   }  //将刚刚FILE* stream的数据流读取到buf中

   

    pclose(stream); 
   return buf;
}

int32_t 
aes_encrypt(uint8_t* in,  char* key, uint8_t* out,int len)
{
    
    assert(in && key && out);
    unsigned char iv[AES_BLOCK_SIZE]; // 加密的初始化向量
    for(int i=0; i<AES_BLOCK_SIZE; ++i){
        iv[i] = 0; 
    }
 
    AES_KEY aes;
    if(AES_set_encrypt_key((const unsigned char*)key, 128, &aes) < 0){
        return -1;
    }
 
    //lyx int len = strlen((char*)in);
    
    len += 16;
    len -= len%16; // 长度 必须是 16 （128位）的整数倍 => 17 + 16 = 33   33-1 = 32;
 
    AES_cbc_encrypt((const unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
    return 0;
}
 
 
int32_t 
aes_decrypt(uint8_t* in,  char* key, uint8_t* out,int len)
{   
     
    if(!in || !key || !out) return -1;
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    
    AES_KEY aes;
    if(AES_set_decrypt_key((unsigned const char*)key, 128, &aes) < 0){
        return -2;
    }
    
   //lyx  int len = strlen((char*)in);
    len += 16;
    len -= len%16;
    AES_cbc_encrypt((unsigned const char*)in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
    return 0;
}
//flag=1,encrypt in into out
//flag=0 decrypt in into out
void preProcessBuf(uint8_t in[],int lenIn,uint8_t out[],int lenOut,int flag,char func[]){
    
    memset( out, '\0',lenOut );
    printf("调用函数 :%s\n",func);
    if(flag ==1){
        
        aes_encrypt(in,key,out,lenIn);
        printf("server:input:%ld,encoded,len %ld\n",strlen((char *)in),strlen((char *)out));//strlen returns the length of a string ended with '\0'
    }
    else{
        aes_decrypt(in,key,out,lenIn);
        printf("server:input:%ld,decoded,len %ld\n",strlen((char *)in),strlen((char *)out));
    }

    return ;
}
