/*********************************************
* 代码贡献：
* 注意事项：
1，第一行加上“#define HAVE_REMOTE”，这样就不要加上头文件 remote-ext.h,也就是说两者效果一样，但推荐前者。
2，很多教程中都只是添加头文件”pcap.h” 会提示相关函数无法解析，需要添加依赖库wpcap.lib
3，代码最后记得pcap_freealldevs()。
*********************************************/
#define HAVE_REMOTE
#include "pcap.h"
#pragma comment(lib,"wpcap.lib")

/*packet handler 函数原型*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
 pcap_if_t *alldevs;
 pcap_if_t *d;
 int inum;
 int i = 0;
 pcap_t *adhandle;
 char errbuf[PCAP_ERRBUF_SIZE];

 //获取本机设备列表
 if(pcap_findalldevs(&alldevs, errbuf) == -1)
 {
  printf("Error in pcap_findalldevs: %s\n", errbuf);
  exit(1);
 }

 //打印列表
 for(d = alldevs; d != NULL; d = d->next)
 {
  printf("%d. %s", ++i, d->name);
  if(d->description)
   printf(" (%s)\n", d->description);
  else
   printf(" (No description available) \n");
 }

 printf("Enter the interface number (1-%d):", i);
 scanf("%d", &inum);
 if(inum < 1 || inum > i)
 {
  printf("\nInterface number out of range.\n");
  //释放设备列表
  pcap_freealldevs(alldevs);
  return -1;
 }

 //跳转到选中的适配器
 for(d = alldevs, i = 0; i < inum -1; d=d->next, i++);

 //打开设备
if ( (adhandle= pcap_open_live(d->name, // name of the device
		65536, // portion of the packet to capture. 65536 grants that the whole packet will be captured on all the MACs.
		1, // 混杂模式
		1000, // 设置超时时间,亳秒为单位
		errbuf // 发生错误时存放错误内容的缓冲区
		) ) == NULL)
 {
  printf("\nUnable to open the adapter.%s is not supported by WinPcap\n", d->name);
  //释放设备列表
  pcap_freealldevs(alldevs);
  return -1;
 }

 printf("\nlistening on %s... \n", d->description);
 //释放设备列表
 pcap_freealldevs(alldevs);

 //开始捕捉
 pcap_loop(adhandle, 0, packet_handler, NULL);

 return 0;
}

//每次捕捉到数据包时，libpcap都会自动调用这个回调函数
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
 struct tm *ltime;
 char timestr[16];
 time_t local_tv_sec;

 //将时间戳转换成可识别的格式
 local_tv_sec = header->ts.tv_sec;
// printf("%d \n", local_tv_sec);
// ltime = localtime(&local_tv_sec);
// strftime(timestr, sizeof(timestr), "%H %M %S", ltime);
 printf("%s,%.6d len:%d\n", ctime(&local_tv_sec), header->ts.tv_usec, header->len);
 printf("%s\n",pkt_data);
}
