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


#include <stdlib.h>
#define _XOPEN_SOURCE 700
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


#include <sys/types.h>
#include <unistd.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <string.h>



#include <dtp_config.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <quiche.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/aes.h>

#define AES_BITS 32*8
#define MSG_LEN 1280

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

#define MAX_BLOCK_SIZE 1000000  // 1Mbytes

const int aesFlag=1;//1 turn the crypto on and 0 turn off
AES_KEY  aaeeskey; //openssl key used for crypto

int cfgs_len = 0;
uint64_t total_bytes = 0;
uint64_t good_bytes = 0;
uint64_t complete_bytes = 0;
uint64_t start_timestamp = 0;
uint64_t end_timestamp = 0;
char * key =NULL;
FILE* CLIENT_LOG = NULL;
FILE* CLIENT_CSV = NULL;
const char* CLIENT_LOG_FILENAME = "client.log";
const char *CLIENT_CSV_FILENAME = "client.csv";

#define WRITE_TO_LOG(...)                                           \
  {                                                                 \
    if(!CLIENT_LOG) {                                               \
      perror("Write to client log fails: file is not opened");      \
    }                                                               \
    fprintf(CLIENT_LOG, __VA_ARGS__);                               \
  }

#define WRITE_TO_CSV(...)                                            \
  {                                                                  \
    if (!CLIENT_CSV) {                                               \
      perror("Write to client csv fails: file is not opened");       \
    }                                                                \
    fprintf(CLIENT_CSV, __VA_ARGS__);                                       \
  }

struct conn_io {
    ev_timer timer;
    ev_timer pace_timer;

    int sock;
    quiche_conn *conn;

    uint64_t t_last;
    ssize_t can_send;
    bool done_writing;
};

// static void debug_log(const char *line, void *argp) {
//     fprintf(stderr, "%s\n", line);
// }
char * getSend(const char * srcip,const char * dstip,const char * proxyaddr);
int32_t aes_encrypt(uint8_t* in,  char* key, uint8_t* out,int len); // 加密
int32_t aes_decrypt(uint8_t* in, char* key, uint8_t* out,int len); // 解密
int32_t 
cfbDE(uint8_t* in,  char* key, uint8_t* out,int len);
int32_t 
cfbEN(uint8_t* in,  char* key, uint8_t* out,int len);
void preCFB(uint8_t in[],int lenIn,uint8_t out[],int lenOut,int flag);
void aes_init(AES_KEY * aesKey,char * srcKey);

static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_DATAGRAM_SIZE];
    static uint8_t encryptedData[MAX_DATAGRAM_SIZE+16];
    uint64_t rate = quiche_bbr_get_pacing_rate(conn_io->conn);  // bits/s
    // uint64_t rate = 48*1024*1024; //48Mbits/s
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
        // fprintf(stderr, "send?\n");
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out));

        if (written == QUICHE_ERR_DONE) {
            // fprintf(stderr, "done writing\n");
            conn_io->pace_timer.repeat = 99999.0;
            ev_timer_again(loop, &conn_io->pace_timer);
            conn_io->done_writing = true;  // app_limited
            break;
        }

        if (written < 0) {
            // fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }
        //sent out with new encryption
        ssize_t sent;
        if(aesFlag==1){
            preCFB(out,written,encryptedData,MAX_DATAGRAM_SIZE+16,1);
          
            sent= send(conn_io->sock, encryptedData, written, 0);
        }
       
        else
            sent= send(conn_io->sock, out, written, 0);
 

        if (sent != written) {
            perror("failed to send");
          //  return;
        }

        // fprintf(stderr, "sent %zd bytes\n", sent);
        conn_io->can_send -= sent;
    }
    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    // fprintf(stderr, "timeout t = %lf\n", t);
    ev_timer_again(loop, &conn_io->timer);
}

static void flush_egress_pace(EV_P_ ev_timer *pace_timer, int revents) {
    struct conn_io *conn_io = pace_timer->data;
    // fprintf(stderr, "begin flush_egress_pace\n");
    flush_egress(loop, conn_io);
}

static void recv_cb(EV_P_ ev_io *w, int revents) {
    struct conn_io *conn_io = w->data;
    static uint8_t buf[MAX_BLOCK_SIZE];
    static uint8_t encryptedbuf[MAX_BLOCK_SIZE+16];
    uint8_t i = 3;

    while (i--) {
        ssize_t read;
        
        if(aesFlag==1){
            read = recv(conn_io->sock, encryptedbuf, sizeof(encryptedbuf), 0);
            preCFB(encryptedbuf,read,buf,MAX_BLOCK_SIZE,0 );
            /*
            printf("\nthe encoded data is:\n");
        for(int i=0;i<read;i++){
            printf("%d ",encryptedbuf[i]);
        }
        printf("\n");
        */

        }
        else
            read = recv(conn_io->sock, buf, sizeof(buf), 0);
      //  printf("\nthe read is :%ld\n",read);
      /*
        for(int i=0;i<read;i++){
            printf("%d ",buf[i]);
        }
        printf("\n");
        
        */
        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                // fprintf(stderr, "recv would block\n");
                break;
            }

            perror("client failed to read");
            return;
        }
        total_bytes += read;
        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read);

        if (done == QUICHE_ERR_DONE) {
            // fprintf(stderr, "done reading\n");
            break;
        }

        if (done < 0) {
            // fprintf(stderr, "failed to process packet\n");
            return;
        }

        // fprintf(stderr, "recv %zd bytes\n", done);
    }

    if (quiche_conn_is_closed(conn_io->conn)) {
        // fprintf(stderr, "connection closed\n");
        quiche_stats stats;

        quiche_conn_stats(conn_io->conn, &stats);
        if(end_timestamp == 0) {
            end_timestamp = getCurrentUsec();
        }
        WRITE_TO_LOG("connection closed, recv=%zu sent=%zu lost=%zu rtt=%fms cwnd=%zu, total_bytes=%zu, complete_bytes=%zu, good_bytes=%zu, total_time=%zu\n",
                stats.recv, stats.sent, stats.lost, stats.rtt / 1000.0 / 1000.0, stats.cwnd,
                total_bytes, complete_bytes, good_bytes, end_timestamp - start_timestamp

        );
        ev_break(EV_A_ EVBREAK_ONE);
        return;
    }

    if (quiche_conn_is_established(conn_io->conn)) {
        uint64_t s = 0;

        quiche_stream_iter *readable = quiche_conn_readable(conn_io->conn);

        while (quiche_stream_iter_next(readable, &s)) {
            // fprintf(stderr, "stream %" PRIu64 " is readable\n", s);

            bool fin = false;
            ssize_t recv_len = quiche_conn_stream_recv(conn_io->conn, s, buf,
                                                       sizeof(buf), &fin);
            /* total_bytes += recv_len; */
            if (recv_len < 0) {
                break;
            }
            if (fin) {
              if (s == 1) {
                // cfgs length
                cfgs_len = *((int*) buf);
                fprintf(stderr, "get cfgs number: %d\n", cfgs_len);
                cfgs_len--;
              } else {
                // output block_size,block_priority,block_deadline
                uint64_t block_size, block_priority, block_deadline;
                int64_t bct = quiche_conn_get_bct(conn_io->conn, s);
                uint64_t goodbytes =
                    quiche_conn_get_good_recv(conn_io->conn, s);
                quiche_conn_get_block_info(conn_io->conn, s, &block_size,
                                           &block_priority, &block_deadline);
                good_bytes += goodbytes;
                complete_bytes += block_size;
                // FILE* clientlog = fopen("client.log", "a+");
                // fprintf(clientlog, "%2ld %14ld %4ld %9ld %5ld %9ld\n", s,
                //         goodbytes, bct, block_size, block_priority,
                //         block_deadline);
                // fclose(clientlog);
                WRITE_TO_LOG("%2ld %10ld %10ld %10ld %10ld\n",
                    s, bct, block_size, block_priority, block_deadline);

                WRITE_TO_CSV("%2ld,%10ld,%10ld,%10ld,%10ld\n", s, bct,
                             block_size, block_priority, block_deadline);
                if (--cfgs_len == 0) {
                  end_timestamp = getCurrentUsec();
                  fprintf(stderr, "end_timestamp: %lu\n", end_timestamp);
                }
              }
            }

            // if (fin) {
            //     if (quiche_conn_close(conn_io->conn, true, 0, NULL, 0) < 0) {
            //         fprintf(stderr, "failed to close connection\n");
            //     }
            // }
        }

        quiche_stream_iter_free(readable);
    }

    flush_egress(loop, conn_io);
}

static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    quiche_conn_on_timeout(conn_io->conn);

    // fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        // fprintf(stderr, "connection closed in timeout \n");
        /* end_timestamp = getCurrentUsec(); */
        quiche_stats stats;

        quiche_conn_stats(conn_io->conn, &stats);

        // FILE* clientlog = fopen("client.log", "a+");
        // fprintf(clientlog, "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64 "ns cwnd=%zu, total_bytes=%zu, complete_bytes=%zu, good_bytes=%zu, total_time=%zu\n",
        //         stats.recv, stats.sent, stats.lost, stats.rtt, stats.cwnd,
        //         total_bytes, complete_bytes, good_bytes, total_time
        //         );
        // fclose(clientlog);
        if(end_timestamp == 0) {
            end_timestamp = getCurrentUsec();
        }
        WRITE_TO_LOG("connection closed\nrecv,sent,lost,rtt(ms),cwnd,total_bytes,complete_bytes,good_bytes,total_time(us)\n%zu,%zu,%zu,%f,%zu,%zu,%zu,%zu,%zu\n",
                stats.recv, stats.sent, stats.lost, stats.rtt / 1000.0 / 1000.0, stats.cwnd,
                total_bytes, complete_bytes, good_bytes, end_timestamp - start_timestamp
        );
        // fprintf(stderr,
        //         "connection closed, recv=%zu sent=%zu lost=%zu rtt=%" PRIu64
        //         "ns\n",
        //         stats.recv, stats.sent, stats.lost, stats.rtt);

        ev_break(EV_A_ EVBREAK_ONE);

        fflush(stdout);
        return;
    }
}
 
int main(int argc, char *argv[]) {

    const char * proxyaddr=argv[3];
    const char *srcip = argv[4];
    const char *dstip = argv[5];

    char * buf=getSend(srcip,dstip,proxyaddr);
    
    key=strstr(buf,"result");
   if (key ==NULL){
       printf("Failed to fetch keys.");
       return 0;
   }
   unsigned int contLen= strlen (key);
 
    key[contLen-1]='\0';
    key[contLen-2]='\0';
    key+=9;
    
    printf("The key is :%s\n",key);
    aes_init(&aaeeskey,key);

    const char *host = argv[1];
    const char *port = argv[2];
   
    CLIENT_LOG = fopen(CLIENT_LOG_FILENAME, "w");
    CLIENT_CSV = fopen(CLIENT_CSV_FILENAME, "w");

    if(CLIENT_LOG == NULL) {
      perror("file open failed: log");
      return -1;
    }

    if (CLIENT_CSV == NULL) {
        perror("file open failed: csv");
        return -1;
    }

    const struct addrinfo hints = {.ai_family = PF_UNSPEC,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};

    // quiche_enable_debug_logging(debug_log, NULL);

    struct addrinfo *peer;
    if (getaddrinfo(host, port, &hints, &peer) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    WRITE_TO_LOG("peer_addr = %s:%s\n", host, port);

    int sock = socket(peer->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    if (connect(sock, peer->ai_addr, peer->ai_addrlen) < 0) {
        perror("failed to connect socket");
        return -1;
    }

    quiche_config *config = quiche_config_new(0xbabababa);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_set_application_protos(
        config, (uint8_t *)"\x05hq-25\x05hq-24\x05hq-23\x08http/0.9", 15);

    quiche_config_set_max_idle_timeout(config, 5000);
    quiche_config_set_max_packet_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000000);
    //quiche_config_set_initial_max_stream_data_uni(config, 1000000000);
    quiche_config_set_initial_max_streams_bidi(config, 10000);
    //quiche_config_set_initial_max_streams_uni(config, 10000);
    //quiche_config_set_disable_active_migration(config, true);
    quiche_config_set_cc_algorithm(config, QUICHE_CC_RENO);

    if (getenv("SSLKEYLOGFILE")) {
        quiche_config_log_keys(config);
    }

    uint8_t scid[LOCAL_CONN_ID_LEN];
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return -1;
    }

    ssize_t rand_len = read(rng, &scid, sizeof(scid));
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return -1;
    }

    quiche_conn *conn =
        quiche_connect(host, (const uint8_t *)scid, sizeof(scid), config);

    start_timestamp = getCurrentUsec();

    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        return -1;
    }

    struct conn_io *conn_io = malloc(sizeof(*conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return -1;
    }

    // fprintf(stdout, "StreamID goodbytes bct BlockSize Priority Deadline\n");

    WRITE_TO_LOG("test begin!\n\n");
    WRITE_TO_LOG("BlockID  bct  BlockSize  Priority  Deadline\n");
    WRITE_TO_CSV("BlockID,bct,BlockSize,Priority,Deadline\n");
    // FILE* clientlog = fopen("client.log", "w");
    // fprintf(clientlog, "StreamID  bct  BlockSize  Priority  Deadline\n");
    // fclose(clientlog);

    conn_io->sock = sock;
    conn_io->conn = conn;
    conn_io->t_last = getCurrentUsec();
    conn_io->can_send = 1350+16;
    conn_io->done_writing = false;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher, recv_cb, conn_io->sock, EV_READ);
    ev_io_start(loop, &watcher);
    watcher.data = conn_io;

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    // ev_timer_init(&conn_io->pace_timer, flush_egress_pace, 99999.0, 99999.0);
    // ev_timer_start(loop, &conn_io->pace_timer);
    ev_init(&conn_io->pace_timer, flush_egress_pace);
    conn_io->pace_timer.data = conn_io;

    flush_egress(loop, conn_io);

    ev_loop(loop, 0);

    freeaddrinfo(peer);

    quiche_conn_free(conn);

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
  //printf("%s",request);
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
//flag=1,encrypt in into out
//flag=0 decrypt in into out
void preCFB(uint8_t in[],int lenIn,uint8_t out[],int lenOut,int flag){
    
   // memset( out, '\0',lenOut );
   
  //  printf("调用函数 :%s\n",func);
     
    if(flag ==1){
        
        cfbEN(in,key,out,lenIn);
     //   printf("server:input:%ld,encoded,len %ld\n",strlen((char *)in),strlen((char *)out));//strlen returns the length of a string ended with '\0'
    } 
    else{
        cfbDE(in,key,out,lenIn);
     
    }

    return ;
}
 
void aes_init(AES_KEY * aesKey,char * srcKey){
    AES_set_encrypt_key((uint8_t*)srcKey, 128, aesKey);
}
