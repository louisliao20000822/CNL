#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<errno.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<sys/time.h>
#define ICMP 0
#define TCP 1
#define UDP 2
#define udprecvport 33438//53
#define tcpsendport 80
char *DNSLookup(char *host){
// TODO
struct addrinfo* address;
int result = getaddrinfo(host, NULL, NULL, &address);
if (result != 0) {
    printf("DNSLookup failed\n");
    exit(0);
}
struct sockaddr_in* ip_addr = (struct sockaddr_in*) address->ai_addr;
strcpy(host,inet_ntoa(ip_addr->sin_addr));
return host;
}
int trace_ICMP(char* dest,char* ip){
int icmpfd;
if((icmpfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)) < 0){
    printf("Can not open socket with error number %d\n", errno);
    exit(1);
}
//int recvfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
struct sockaddr_in sendAddr;
sendAddr.sin_port = htons (7);
sendAddr.sin_family = AF_INET;
inet_pton(AF_INET, ip, &(sendAddr.sin_addr));

// Set timeout use setsocketopt
// TODO
struct timeval recvtimeout;
recvtimeout.tv_sec = 1;
recvtimeout.tv_usec = 0;
int ret;
if(setsockopt(icmpfd, SOL_SOCKET, SO_RCVTIMEO, &recvtimeout, sizeof(recvtimeout))<0){
    printf("setsockopt fail%d\n",errno);
    exit(0);
}
int TTL;
unsigned short cksum;
int finish = 0; // if the packet reaches the destination
int maxHop = 64; // maximum hops 64
struct icmp sendICMP; 
struct timeval begin, end; // used to record RTT
int seq = 0; // increasing sequence number for icmp packet
int count = 3; // sending count for each ttl 3
printf("traceroute to %s (%s), %d hops max\n", dest, ip, maxHop);
int c,h;
for(h = 1; h < maxHop; h++){
    // Set TTL use setsockopt
    // TODO
    char srcIP[4][32];
    float interval[4] = {};
    TTL = h;
    if(setsockopt(icmpfd,IPPROTO_IP,IP_TTL,&TTL,sizeof(TTL))<0){
        printf("setsockopt fail%d\n",errno);
        exit(0);
    }
    for(c = 0; c < count; c++){
        int tvout = 0;//check timeout
        if(c==0)
            printf("ttl:%d",h);
        // Set ICMP Header
        // TODO
        sendICMP.icmp_type = 8;
        sendICMP.icmp_code = 0;
        sendICMP.icmp_cksum = 0;
        sendICMP.icmp_id = 1;
        sendICMP.icmp_seq = seq;
       
        //Checksum
        // TODO
        int totalByte = sizeof(sendICMP);
        unsigned int sum = 0;
        unsigned short* addr = (unsigned short*)&sendICMP;
        while(totalByte>1){
            sum+=*addr;
            addr++;
            totalByte -= 2;
        }
        if(totalByte>0)
             sum+=*(unsigned char*) addr;
        while(sum>>16)
            sum = (sum & 0xffff) + (sum>>16);
        cksum = ~sum;
        sendICMP.icmp_cksum = cksum;
        
        // Send the icmp packet to destination
        // TODO
        
        double diff;
        gettimeofday(&begin,NULL);
        
        // printf("begintv_sec:%ld\n",begin.tv_sec);
        // printf("begintv_usec:%ld\n",begin.tv_usec);
        ret = sendto(icmpfd,&sendICMP,sizeof(struct icmp),0,(struct sockaddr *)&sendAddr,sizeof(sendAddr));
        if(ret==-1)
            printf("fail sendto!!!\n");
        // Recive ICMP reply, need to check the identifier and sequence number
        struct ip *recvIP;
        struct icmp *recvICMP;
        struct sockaddr_in recvAddr;
        u_int8_t icmpType = 8;
        unsigned int recvLength = sizeof(recvAddr);
        char recvBuf[1500];
        char hostname[4][128];
        memset(&recvAddr, 0, sizeof(struct sockaddr_in));
        // TODO
        memset(&recvBuf,0,sizeof(recvBuf));
        while((icmpType!=0)&&(icmpType!=11)){
            ret = recvfrom(icmpfd,recvBuf,sizeof(recvBuf),0,(struct sockaddr *)&recvAddr,&recvLength);
            if(ret==-1){
                if((errno==EAGAIN)||(errno==EWOULDBLOCK)){
                    interval[c] = -1;
                    strcpy(srcIP[c],"*");
                }
            tvout = 1;
            break;
            }
            recvIP = (struct ip*)recvBuf;
            recvICMP = (struct icmp*)(recvBuf+recvIP->ip_hl*4);
            icmpType = recvICMP->icmp_type;
        }
        if(tvout)
            continue;//timeout
        gettimeofday(&end,NULL);
        diff = (end.tv_sec-begin.tv_sec)*1000+(end.tv_usec-begin.tv_usec)/1000.0;
        //printf("%fms\n",diff);
        interval[c] = diff;
        // printf("endtv_sec:%ld\n",start.tv_sec);
        // printf("endtv_usec:%ld\n",start.tv_usec);
        #ifdef DEBUG
        printf("types:%u\n",recvICMP->icmp_type);
        printf("identifier:%hu\n",recvICMP->icmp_id);
        printf("checksum:%04x\n",recvICMP->icmp_cksum);
        #endif
        // Get source hostname and ip address 
        getnameinfo((struct sockaddr *)&recvAddr, sizeof(recvAddr), hostname[c], sizeof(hostname[c]), NULL, 0, 0); 
        strcpy(srcIP[c], inet_ntoa(recvIP->ip_src));
        if(icmpType == 0){
            finish = 1;
        }
        
        // Print the result
        // TODO
    }
    int flag=0;
    for(int i=0; i<count;i++){
        if(interval[i]!=-1){
            printf("    IP:%s",srcIP[i]);
            flag = 1;
            break;
        }
    }
    if(flag==0)
        printf("    IP:*");
     for(int i=0; i<count;i++){
        if(interval[i]!=-1)
            printf("    RTT:%fms",interval[i]);
        else
            printf("    Timeout");
    }
    printf("\n");
    if(finish){
        break;
    }
}
close(icmpfd);
return 0;
}
int trace_UDP(char* dest,char* ip){                             //reference:https://blog.csdn.net/C3080844491/article/details/77817028
int sendfd,recvfd;
if((sendfd = socket(AF_INET , SOCK_DGRAM , 0)) < 0){
    printf("Can not open socket with error number %d\n", errno);
    exit(1);
}
if((recvfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)) < 0){  //before connect
    printf("Can not open socket with error number %d\n", errno);
    exit(1);
}

struct sockaddr_in sendAddr,destAddr;
bzero(&destAddr,sizeof(destAddr));
destAddr.sin_family = AF_INET;
destAddr.sin_addr.s_addr = inet_addr(ip);
destAddr.sin_port = htons (udprecvport);
memset(destAddr.sin_zero, 0, sizeof(destAddr.sin_zero));  
bzero(&sendAddr,sizeof(sendAddr));
sendAddr.sin_family = AF_INET;
sendAddr.sin_port = htons (7414);
memset(sendAddr.sin_zero, 0 , sizeof(sendAddr.sin_zero));  
if (bind(sendfd, (struct sockaddr *)&sendAddr, sizeof(sendAddr)) < 0) {
    printf("Can not bind socket with error number %d\n", errno);
    exit(1);
}
struct timeval begin, end; // used to record RTT
int count = 3; // sending count for each ttl 3
int maxHop = 64; // maximum hops 64
int finish = 0; // if the packet reaches the destination
int ret;
int TTL;
struct sockaddr_in recvAddr;
struct timeval recvtimeout;
recvtimeout.tv_sec = 1;
recvtimeout.tv_usec = 0;
if(setsockopt(recvfd, SOL_SOCKET, SO_RCVTIMEO, &recvtimeout, sizeof(recvtimeout))<0){
    printf("setsockopt fail%d\n",errno);
    exit(0);
}
memset(&recvAddr, 0, sizeof(struct sockaddr_in));
unsigned int recvLength = sizeof(recvAddr);
char sendBuf[1500];
char recvBuf[1500];
struct ip *recvIP;
struct icmp *recvICMP;
u_int8_t icmpType = 8;
char hostname[4][128];
char srcIP[4][32];
float interval[4] = {};
int c,h,i;
double diff;
for(h = 1; h < maxHop ;h++){
    TTL = h;
    if(setsockopt(sendfd,IPPROTO_IP,IP_TTL,&TTL,sizeof(TTL))<0){
        printf("setsockopt fail%d\n",errno);
        exit(0);
    } 
    for(c = 0; c < count; c++){
        int tvout = 0;//check timeout
        if(c==0)
            printf("ttl:%d",h);
        memset(sendBuf, 0 ,sizeof(sendBuf));
        gettimeofday(&begin,NULL);
        ret = sendto(sendfd,sendBuf,sizeof(sendBuf), 0 ,(struct sockaddr *)&destAddr,sizeof(destAddr));
        
        ret = recvfrom(recvfd,recvBuf,sizeof(recvBuf),0,(struct sockaddr *)&recvAddr,&recvLength);
        if(ret==-1){
            if((errno==EAGAIN)||(errno==EWOULDBLOCK)){
                    interval[c] = -1;
                    strcpy(srcIP[c],"*");
            }
            tvout = 1;
        }
        if(tvout)
            continue;//timeout
        recvIP = (struct ip*)recvBuf;
        recvICMP = (struct icmp*)(recvBuf+recvIP->ip_hl*4);
        icmpType = recvICMP->icmp_type;
        if((icmpType!=ICMP_TIME_EXCEEDED)&&(icmpType!=ICMP_DEST_UNREACH))
            printf("wrong ICMP type with%d\n",icmpType);
        gettimeofday(&end,NULL);
        diff = (end.tv_sec-begin.tv_sec)*1000+(end.tv_usec-begin.tv_usec)/1000.0;
        interval[c] = diff;
        getnameinfo((struct sockaddr *)&recvAddr, sizeof(recvAddr), hostname[c], sizeof(hostname[c]), NULL, 0, 0);  
        strcpy(srcIP[c], inet_ntoa(recvIP->ip_src));
        if(icmpType == ICMP_DEST_UNREACH){
            finish = 1;
        }
        
    }
    int flag=0;
    for(i = 0; i < count; i++){
        if(interval[i]!=-1){
            printf("    IP:%s",srcIP[i]);
            flag = 1;
            break;
        }
    }
    if(flag==0)
        printf("    IP:*");
     for(i=0; i<count;i++){
        if(interval[i]!=-1)
            printf("    RTT:%fms",interval[i]);
        else
            printf("    Timeout");
    }
    printf("\n");
    if(finish){
        break;
    }
}       
return 0;
}
int trace_TCP(char* dest,char* ip){
int sendfd,recvfd,icmpfd;
if((icmpfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)) < 0){  //before connect
    printf("Can not open socket with error number %d\n", errno);
    exit(1);
}
if((recvfd = socket(AF_INET,SOCK_RAW,IPPROTO_TCP)) < 0){  //before connect
    printf("Can not open socket with error number %d\n", errno);
    exit(1);
}
if((sendfd = socket(AF_INET , SOCK_STREAM , 0)) < 0){
    printf("Can not open socket with error number %d\n", errno);
    exit(1);
}

struct sockaddr_in sendAddr;
bzero(&sendAddr,sizeof(sendAddr));
sendAddr.sin_family = AF_INET;
sendAddr.sin_addr.s_addr = inet_addr(ip);
sendAddr.sin_port = htons (tcpsendport);
struct timeval begin, end; // used to record RTT
int count = 3; // sending count for each ttl 3
int maxHop = 64; // maximum hops 64
int ret;
int TTL;
struct sockaddr_in recvAddr;
unsigned int recvLength = sizeof(recvAddr);
char recvBuf[1500];
struct ip *recvIP;
struct icmp *recvICMP;
u_int8_t icmpType = 8;
char hostname[4][128];
char srcIP[4][32];
float interval[4] = {};
int c,h,i;
int finish=0;
double diff;
//set timeout
struct timeval recvtimeout;
recvtimeout.tv_sec = 1;
recvtimeout.tv_usec = 0;
if(setsockopt(icmpfd, SOL_SOCKET, SO_RCVTIMEO, &recvtimeout, sizeof(recvtimeout))<0){
    printf("setsockopt fail%d\n",errno);
    exit(0);
}
if(setsockopt(recvfd, SOL_SOCKET, SO_RCVTIMEO, &recvtimeout, sizeof(recvtimeout))<0){
    printf("setsockopt fail%d\n",errno);
    exit(0);
}

if(strcmp("127.0.0.1",ip)==0){
    TTL = 1;
    if(setsockopt(sendfd,IPPROTO_IP,IP_TTL,&TTL,sizeof(TTL))<0){
        printf("setsockopt fail%d\n",errno);
        exit(0);
    }
    for(c = 0; c < count ; c++){
        sendfd = socket(AF_INET , SOCK_STREAM , 0);
        gettimeofday(&begin,NULL);
        connect(sendfd,(struct sockaddr *)&sendAddr,sizeof(sendAddr)); //send SYN
        memset(&recvAddr, 0, sizeof(struct sockaddr_in));
        memset(&recvBuf,0,sizeof(recvBuf));
        ret = recvfrom(recvfd,recvBuf,sizeof(recvBuf),0,(struct sockaddr *)&recvAddr,&recvLength);
        recvIP = (struct ip*)recvBuf;
        gettimeofday(&end,NULL);
        diff = (end.tv_sec-begin.tv_sec)*1000+(end.tv_usec-begin.tv_usec)/1000.0;
        interval[c] = diff;
        getnameinfo((struct sockaddr *)&recvAddr, sizeof(recvAddr), hostname[c], sizeof(hostname[c]), NULL, 0, 0);  
        strcpy(srcIP[c], inet_ntoa(recvIP->ip_src));
        if(c==0)
            printf("ttl:%d    IP:%s    RTT:%fms",TTL,srcIP[c],interval[c]);
        else
            printf("    RTT:%fms",interval[c]);
        struct linger L={1,0};
        setsockopt(sendfd,SOL_SOCKET,SO_LINGER,&L,sizeof(&L));
        close(sendfd);
    }
    printf("\n");
}
else{
for(h = 1; h < maxHop ; h++){
TTL = h;
if(setsockopt(sendfd,IPPROTO_IP,IP_TTL,&TTL,sizeof(TTL))<0){
    printf("setsockopt fail%d\n",errno);
    exit(0);
}
for(c = 0; c < count ; c++){
if(c==0)
    printf("ttl:%d",h);
int tvout = 0;//check timeout
gettimeofday(&begin,NULL);
if(finish){
    sendfd = socket(AF_INET , SOCK_STREAM , 0);
    connect(sendfd,(struct sockaddr *)&sendAddr,sizeof(sendAddr)); //send SYN
    memset(&recvAddr, 0, sizeof(struct sockaddr_in));
    memset(&recvBuf,0,sizeof(recvBuf));
    ret = recvfrom(recvfd,recvBuf,sizeof(recvBuf),0,(struct sockaddr *)&recvAddr,&recvLength);
    recvIP = (struct ip*)recvBuf;
    gettimeofday(&end,NULL);
    diff = (end.tv_sec-begin.tv_sec)*1000+(end.tv_usec-begin.tv_usec)/1000.0;
    interval[c] = diff;
    getnameinfo((struct sockaddr *)&recvAddr, sizeof(recvAddr), hostname[c], sizeof(hostname[c]), NULL, 0, 0);  
    strcpy(srcIP[c], inet_ntoa(recvIP->ip_src));
}
else{
connect(sendfd,(struct sockaddr *)&sendAddr,sizeof(sendAddr)); //send SYN
memset(&recvAddr, 0, sizeof(struct sockaddr_in));
memset(&recvBuf,0,sizeof(recvBuf));
ret = recvfrom(icmpfd,recvBuf,sizeof(recvBuf),0,(struct sockaddr *)&recvAddr,&recvLength);
if(ret==-1){
    if((errno==EAGAIN)||(errno==EWOULDBLOCK)){
        interval[c] = -1;
        strcpy(srcIP[c],"*");
    }
    ret = recvfrom(recvfd,recvBuf,sizeof(recvBuf),0,(struct sockaddr *)&recvAddr,&recvLength);
    if(ret==-1){
        if((errno==EAGAIN)||(errno==EWOULDBLOCK))
            continue;
    }
    else{
        recvIP = (struct ip*)recvBuf;
        gettimeofday(&end,NULL);
        diff = (end.tv_sec-begin.tv_sec)*1000+(end.tv_usec-begin.tv_usec)/1000.0;
        diff -= 1000;
        interval[c] = diff;
        getnameinfo((struct sockaddr *)&recvAddr, sizeof(recvAddr), hostname[c], sizeof(hostname[c]), NULL, 0, 0);  
        strcpy(srcIP[c], inet_ntoa(recvIP->ip_src));
        struct linger L={1,0};
        setsockopt(sendfd,SOL_SOCKET,SO_LINGER,&L,sizeof(&L));
        close(sendfd);
        finish = 1;
    }

}
else{
recvIP = (struct ip*)recvBuf;
recvICMP = (struct icmp*)(recvBuf+recvIP->ip_hl*4);
icmpType = recvICMP->icmp_type;
if(icmpType!=11)
    printf("error ICMP type\n");
gettimeofday(&end,NULL);
diff = (end.tv_sec-begin.tv_sec)*1000+(end.tv_usec-begin.tv_usec)/1000.0;
interval[c] = diff;
getnameinfo((struct sockaddr *)&recvAddr, sizeof(recvAddr), hostname[c], sizeof(hostname[c]), NULL, 0, 0);  
strcpy(srcIP[c], inet_ntoa(recvIP->ip_src));

}
}
}
int flag=0;
    for(i = 0; i < count; i++){
        if(interval[i]!=-1){
            printf("    IP:%s",srcIP[i]);
            flag = 1;
            break;
        }
    }
    if(flag==0)
        printf("    IP:*");
     for(i=0; i<count;i++){
        if(interval[i]!=-1)
            printf("    RTT:%fms",interval[i]);
        else
            printf("    Timeout");
    }
printf("\n");
if(finish)
    break;
   
   

}

}
close(recvfd);
close(icmpfd); 
return 0;
}
int main(int argc, char *argv[]){
char *type = argv[1];
char *dest = argv[2];
char *ip = DNSLookup(dest);
if(ip == NULL){
    printf("traceroute: unknown host %s\n", dest);
    exit(1);
}
int Type;
if(strcmp(type,"-I")==0)
    Type = ICMP;
else if(strcmp(type,"-U")==0)
    Type = UDP;
else if(strcmp(type,"-T")==0)
    Type = TCP;
else{
    printf("bad command\n");
    exit(0);
}
switch(Type){
    case ICMP:
        trace_ICMP(dest,ip);
        break;
    case UDP:
        trace_UDP(dest,ip);
        break;
    case TCP:
        trace_TCP(dest,ip);
        break;
}
return 0;
}