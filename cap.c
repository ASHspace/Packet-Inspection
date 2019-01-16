#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <ctype.h>
#include <string.h>

#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif


u_int16_t handle_ethernet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
u_char* handle_IP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);

char check[100];

struct my_ip {
    u_int8_t    ip_vhl;  
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
    u_int8_t    ip_tos;     
    u_int16_t   ip_len;    
    u_int16_t   ip_id;     
    u_int16_t   ip_off;    
#define IP_DF 0x4000       
#define IP_MF 0x2000       
#define IP_OFFMASK 0x1fff  
    u_int8_t    ip_ttl;    
    u_int8_t    ip_p;       
    u_int16_t   ip_sum;     
    struct  in_addr ip_src,ip_dst;  
};


void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    static int count = 1, s_count=0;
    int i = 0,j=0;
    char t_data[pkthdr->len];

    fprintf(stdout,"\nPacket No: %d\n",count);
    fprintf(stdout,"Packet Size: %d\n", pkthdr->len);    

    for(i=0;i<pkthdr->len;i++) { 
        if(isprint(packet[i])){              
            t_data[j]=  packet[i];
            j++; 
        }
    }

    if(t_data!= NULL)
        {
           
            if(strstr(t_data, check) != NULL) {
               printf("Search Count: %d\n",++s_count);
               printf("========================= Payload =========================\n");
               for(i=0;i<pkthdr->len;i++) { 
        			if(isprint(packet[i]))               
            			printf("%c",packet[i]);          
        			else
            			fprintf(stdout,".");          
        			if((i%59==0 && i!=0) || i==pkthdr->len-1) 
            			printf("\n"); 
   				}
   				printf("===========================================================\n");
            }
            else
            	printf("Search Count: %d\n",s_count);
            t_data[0]='\0';
        }


    fflush(stdout);
    count++;

    u_int16_t type = handle_ethernet(args,pkthdr,packet);

      if(type == ETHERTYPE_IP)
    {
        handle_IP(args,pkthdr,packet);
    }else if(type == ETHERTYPE_ARP)
    {
    }
    else if(type == ETHERTYPE_REVARP)
    {
    }    
}

u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int i;

    int len;

    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d",length);
        return NULL;
    }

    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip); 
    version = IP_V(ip);

    if(version != 4)
    {
      fprintf(stdout,"Unknown version %d\n",version);
      return NULL;
    }

    if(hlen < 5 )
    {
        fprintf(stdout,"bad-hlen %d \n",hlen);
    }

    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )
    {
        fprintf(stdout,"\nIP Address: ");
        fprintf(stdout,"From: %s",
                inet_ntoa(ip->ip_src));
        fprintf(stdout," To: %s \n",
                inet_ntoa(ip->ip_dst));
    }

    return NULL;
}

u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;  
    u_short ether_type;

    if (caplen < ETHER_HDRLEN)
    {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

     eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    fprintf(stdout,"Ethernet header: ");
    fprintf(stdout,"%s "
            ,ether_ntoa((struct ether_addr*)eptr->ether_shost));
    fprintf(stdout,"%s "
            ,ether_ntoa((struct ether_addr*)eptr->ether_dhost));

    if (ether_type == ETHERTYPE_IP)
    {
        fprintf(stdout,"(IP)");
    }else  if (ether_type == ETHERTYPE_ARP)
    {
        fprintf(stdout,"(ARP)");
    }else  if (eptr->ether_type == ETHERTYPE_REVARP)
    {
        fprintf(stdout,"(RARP)");
    }else {
        fprintf(stdout,"(?)");
    }

    return ether_type;
}


int main(int argc,char **argv)
{ 
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     
    struct ether_header *eptr;  
    struct bpf_program fp;      
    bpf_u_int32 maskp;          
    bpf_u_int32 netp;           
    char filter_exp[100];


    strcpy(filter_exp,argv[1]);
    strcpy(check,argv[3]);


    if(argc != 4){ fprintf(stdout,"Usage: cap \"options\" i search\n");return 0;}

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { fprintf(stderr,"%s\n",errbuf); exit(1); }

    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

    if(pcap_compile(descr,&fp,filter_exp,0,netp) == -1)
    { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

    if(pcap_setfilter(descr,&fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }

    pcap_loop(descr,atoi(argv[2]),my_callback,NULL);

    return 0;
}
