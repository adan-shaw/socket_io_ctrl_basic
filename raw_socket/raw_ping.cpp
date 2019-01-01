//编译:
//g++ -ggdb3 -o x ./raw_ping.cpp -lpthread


//利用原始套接字, 制造ping 工具.

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h> //bzero
#include <netdb.h>
#include <pthread.h>



//保存已经发送包的状态值
typedef struct ping_packet{
	struct timeval tv_begin;//发送的时间
	struct timeval tv_end;//接收到的时间
	short seq;//序列号
	int flag;//1, 表示已经发送但没有接收到回应包; 0, 表示接收到回应包.
}ping_packet;
ping_packet __ping_buf[128];


#define K 1024 //定义数量级(kb)
#define BUFFERSIZE 72 //发送缓冲区大小
static char recv_buff[2*K]; //为防止接收溢出, 接收缓冲区设置大一些


pid_t pid=0;//进程PID
bool b_running = 0;//running 开关, 启动后, b_running = 1.
short packet_send = 0;//已经发送的数据包有多少
short packet_recv = 0;//已经接收的数据包有多少

struct timeval tv_begin, tv_end, tv_interval;//全局时间记录器


#define url_len_max 256
static char dest_url[url_len_max];//目的主机的ip / url
const char target_ip_url[] = "192.168.5.1";//for test
int sfd_raw = 0;//raw socket 描述符





//*******
//函数声明
//*******
//终端信号处理函数SIGINT
void deal_sig_ping_stop(int signo);
//打印全部的ICMP发送, 接收统计结果
void icmp_statistics(void);

//CRC16校验和计算icmp_cksum
unsigned short icmp_cksum(unsigned char *data,  int len);
//计算时间差time_sub
struct timeval icmp_tvsub(struct timeval end,struct timeval begin);


//查找一个合适的包位置(用于send/recv)
ping_packet* icmp_findpacket(int seq);
//设置ICMP报头
void icmp_pack(struct icmp *icmph, int seq, struct timeval *tv, int length);
//发送icmp 报文
void* icmp_send(void *argv);
//解压接收到的包, 并打印信息
int icmp_unpack(char *buf,int len);
//接收icmp 报文(接收ping 目的主机的回复)
void* icmp_recv(void *argv);











//主程序
int main(void){
  if(url_len_max < strlen(target_ip_url)+1){
    printf("dest_url is too long!! dest_url=%d\n", dest_url);
    return -1;
  }
  else
    memcpy(dest_url,  target_ip_url, strlen(target_ip_url)+1);


  //显示pid
  pid = getuid();
  printf("raw_ping pid = %d\n\n", pid);


  //获取icmp 协议的'协议栈编号', 协议栈不能用字符串来代替.
  struct protoent *protocol = NULL;
  protocol = getprotobyname("icmp");
  if (protocol == NULL){
    printf("getprotobyname fail, errno = %d\n", errno);
    return -1;
  }


  //创建raw socket fd
  sfd_raw = socket(AF_INET, SOCK_RAW, protocol->p_proto);
  if(sfd_raw == -1){
    printf("socket fail, errno = %d\n", errno);
    return -1;
  }


  //增大接收缓冲区, 防止接收的包被覆盖
  int recv_buf_max = 256*K;
  int tmpx = setsockopt(sfd_raw, SOL_SOCKET, SO_RCVBUF,\
               &recv_buf_max, sizeof(recv_buf_max));
  if(tmpx == -1){
    printf("setsockopt fail, errno = %d\n", errno);
    return -1;
  }



  
  //复制目的地址字符串

  memset(__ping_buf, 0, sizeof(ping_packet) * 128);


  //设置ping 目的地址info
  struct sockaddr_in target_addr;
  bzero(&target_addr, sizeof(target_addr));
  target_addr.sin_family = AF_INET;

  unsigned long inaddr = inet_addr(target_ip_url);
  //判断target_ip_url 是ip or url??
  //如果target_ip_url 输入字符串inet_addr() 转换失败, 则表示输入的是url.
  if(inaddr == INADDR_NONE){
    //输入的是url, 向dns 查询ip
    struct hostent* host = gethostbyname(target_ip_url);
    if(host == NULL){
      printf("gethostbyname fail, errno = %d\n", errno);
      return -1;
    }
    //将地址复制到target_addr中
    memcpy((char *)&target_addr.sin_addr, host->h_addr, host->h_length);
  }
  else{
    //输入的是IP地址, inet_addr() 转换成功, 直接赋值.
    memcpy((char*)&target_addr.sin_addr, &inaddr, sizeof(inaddr));
  }

  //打印提示
  inaddr = target_addr.sin_addr.s_addr;
  printf("PING %s (%ld.%ld.%ld.%ld) 56(84) bytes of data.\n", 
    dest_url, 
    (inaddr&0x000000FF)>>0,
    (inaddr&0x0000FF00)>>8,
    (inaddr&0x00FF0000)>>16,
    (inaddr&0xFF000000)>>24);





  //设置终止信号处理函数.
  if(signal(SIGINT, deal_sig_ping_stop) == SIG_ERR){
    printf("signal fail, errno = %d\n", errno);
    return -1;
  }
  //启动running 开关
  b_running = 1;



  //建立两个线程, 用于发送和接收
  pthread_t send_id, recv_id;
  tmpx = pthread_create(&send_id, NULL, icmp_send, &target_addr);//发送
  if(tmpx == -1){
    printf("pthread_create fail, errno = %d\n", errno);
    return -1;
  }
  tmpx = pthread_create(&recv_id, NULL, icmp_recv, NULL);//接收
  if(tmpx == -1){
    printf("pthread_create fail, errno = %d\n", errno);
    return -1;
  }

  //等待线程结束
  tmpx = pthread_join(send_id, NULL);
  if(tmpx != 0){
    printf("pthread_join fail, errno = %d\n", errno);
    return -1;
  }
  tmpx = pthread_join(recv_id, NULL);
  if(tmpx != 0){
    printf("pthread_join fail, errno = %d\n", errno);
    return -1;
  }

  //清理资源
  shutdown(sfd_raw,2);
  close(sfd_raw);


  icmp_statistics();//打印ping 结果

  return 0;
}





//终端信号处理函数SIGINT
void deal_sig_ping_stop(int signo){
  b_running = 0;//告诉接收和发送线程结束程序	
  gettimeofday(&tv_end, NULL);//读取程序结束时间	
  tv_interval = icmp_tvsub(tv_end, tv_begin);//计算一下总共所用时间

  return;
}





//打印全部的ICMP发送, 接收统计结果
void icmp_statistics(void){
  printf("\n\n\n***ping program has finished***\n\n");
  printf("--- %s ping statistics ---\n",dest_url);//目的IP地址
  printf("%d packets transmitted, %d received\n",
          packet_send,//发送总计
          packet_recv);//接收总计
  printf(" %d%% packet loss, time %ldms\n",
    (packet_send-packet_recv)*100 / packet_send,//丢失百分比
    (tv_interval.tv_sec*1000 ) + (tv_interval.tv_usec/1000));//时间总消耗
  return;
}





/*
CRC16校验和计算icmp_cksum
参数：
  data:数据
  len:数据长度
返回值：
  计算结果, short类型
*/
unsigned short icmp_cksum(unsigned char *data, int len){
  int sum = 0;

  //将数据按照2字节为单位累加起来
  while(len & 0xfffe){
    sum += *(unsigned short*)data;
    data += 2;
    len -=2;
  }

  //判断是否为奇数个数据, 若ICMP报头为奇数个字节, 会剩下最后一字节
  //令len 与 0x01 进行'与'位运算, len = 0, 则if = false, 否则len != 0, if = true
  if(len & 0x01){
    unsigned short tmp = ((*data)<<8)&0xff00;
    sum += tmp;
  }
  sum = (sum >>16) + (sum & 0xffff);//高低位相加
  sum += (sum >>16);//将溢出位加入

  return ~sum;//返回取反值
}





/*
计算时间差time_sub
参数：
  end, 接收到的时间
  begin, 开始发送的时间
返回值：
  使用的时间
*/
struct timeval icmp_tvsub(struct timeval end,struct timeval begin){
  struct timeval tv;
  //计算差值
  tv.tv_sec = end.tv_sec - begin.tv_sec;
  tv.tv_usec = end.tv_usec - begin.tv_usec;
  //如果接收时间的usec值小于发送时的usec值, 从usec域借位
  if(tv.tv_usec < 0){
    tv.tv_sec --;
    tv.tv_usec += 1000000; 
  }

  return tv;
}





//查找一个合适的包位置
//*当seq为-1时, 表示查找空包
//*其他值表示查找seq对应的包
ping_packet* icmp_findpacket(int seq){
  int i = 0;
  ping_packet* found = NULL;

  //查找包的位置
  if(seq == -1){//查找空包的位置
    for(;i<128;i++){
      if(__ping_buf[i].flag == 0){
        found = &__ping_buf[i];
        break;
      }
    }
  }
  else if(seq >= 0){//查找对应seq的包
    for(i = 0;i<128;i++){
      if(__ping_buf[i].seq == seq){
        found = &__ping_buf[i];
        break;
      }
    }
  }
  return found;
}





//设置ICMP报头
void icmp_pack(struct icmp *icmph, int seq, struct timeval *tv, int length ){
  //设置报头
  icmph->icmp_type = ICMP_ECHO; //ICMP回显请求
  icmph->icmp_code = 0;         //code值为0
  icmph->icmp_cksum = 0;        //先将cksum值填写0, 便于之后的cksum计算
  icmph->icmp_seq = seq;        //本报的序列号
  icmph->icmp_id = pid &0xffff; //填写PID

  unsigned char i = 0;
  for(; i< length; i++)
    icmph->icmp_data[i] = i;

  //计算校验和
  icmph->icmp_cksum = icmp_cksum((unsigned char*)icmph, length);
  return;
}





//发送ICMP报文
void* icmp_send(void *argv){
  //集成目标addrinfo 结构体
  struct sockaddr* ptarget_addr = (struct sockaddr*)argv;

  //保存程序开始发送数据的时间
  gettimeofday(&tv_begin, NULL);

  while(b_running){
    struct timeval tv;
    gettimeofday(&tv, NULL);//当前包的发送时间

    //在发送包状态数组中找一个空闲位置
    ping_packet *packet = icmp_findpacket(-1);
    if(packet){
      packet->seq = packet_send;//设置seq
      packet->flag = 1;//已经使用
      gettimeofday(&packet->tv_begin, NULL);//发送时间
    }
    //打包数据
    char send_buff[BUFFERSIZE];
    icmp_pack((struct icmp *)send_buff, packet_send, &tv, 64);

    //执行发送操作
    int size = sendto(sfd_raw, send_buff, 64, 0,
               (struct sockaddr*)ptarget_addr, sizeof(struct sockaddr));
    if(size == -1){
      printf("sendto fail, errno = %d\n", errno);
      break;//不允许出错
    }
    else{
      packet_send++;//计数增加
      sleep(1);//每隔1s, 发送一个ICMP回显请求包
    }
  }//while end

  b_running = 0;//一旦线程退出, 程序也跟着中断.
  return NULL;//pthread end
}





//解压接收到的包, 并打印信息
int icmp_unpack(char *buf,int len){
  struct ip* ip_head = (struct ip*)buf;//获取IP 报的'数据段'
  int iphdrlen = ip_head->ip_hl*4;     //IP 报的长度
  struct icmp* icmp=(struct icmp*)(buf+iphdrlen);//获取ICMP 报的'数据段'


  len-=iphdrlen;//计算去除ICMP 报文后, 剩余的长度是多少??
  if(len<8){//判断'剩余长度'是否符合'ICMP包的特征'
    printf("ICMP packets\'s length is less than 8\n");
    return -1;
  }


  //ICMP类型为ICMP_ECHOREPLY并且为本进程的PID
  if((icmp->icmp_type==ICMP_ECHOREPLY) && (icmp->icmp_id== pid)){
    //在发送表格中查找已经发送的包, 按照seq
    ping_packet* packet = icmp_findpacket(icmp->icmp_seq);
    if(packet == NULL)
      return -1;
    packet->flag = 0;	//取消标志

    struct timeval tv_internel,tv_recv,tv_send;
    tv_send = packet->tv_begin;			//获取本包的发送时间
    gettimeofday(&tv_recv, NULL);		//读取此时间, 计算时间差
    tv_internel = icmp_tvsub(tv_recv,tv_send);
    int rtt = tv_internel.tv_sec*1000+tv_internel.tv_usec/1000;


    //打印结果, 包含
    printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n",
      len,//ICMP段长度
      inet_ntoa(ip_head->ip_src),//源IP地址
      icmp->icmp_seq,//包的序列号
      ip_head->ip_ttl,//TTL
      rtt);//时间差

    packet_recv++;//接收包数量加1
    return 0;
  }//if end
  else{
    return -1;
  }
}





//接收icmp 报文(接收ping目的主机的回复)
void *icmp_recv(void *argv){
  //轮询等待时间
  struct timeval tv;
  tv.tv_usec = 200;
  tv.tv_sec = 0;

  //当没有信号发出一直接收数据
  while(b_running){
    //初始化fd_set
    fd_set fd_set_r;
    FD_ZERO(&fd_set_r);
    FD_SET(sfd_raw, &fd_set_r);

    int ret = select(sfd_raw+1,&fd_set_r, NULL, NULL, &tv);
    switch(ret){
      case -1:
        //错误发生
        break;
      case 0:
        //超时
        break;
      default:
        {
          //接收数据
          int size = recv(sfd_raw, recv_buff, sizeof(recv_buff), 0);
          if(errno == EINTR){
            printf("recv fail, errno = %d\n", errno);
            continue;
          }

          //解包, 并设置相关变量
          ret = icmp_unpack(recv_buff, size);
          if(ret == -1){
            break;//不允许出错
          }
        }
        break;
    }//switch end
  }//while end

  b_running = 0;//一旦线程退出, 程序也跟着中断.
  return NULL;//pthread end
}
