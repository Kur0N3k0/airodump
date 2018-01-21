#include <pcap.h>
#include <ctype.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "wireless.h"

int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		char *buf = NULL;
		const u_char *packet;		/* The actual packet */
		int res;
		int i;

		if(argc != 2){
			printf("[Usage] ./pcap [network_device]\n");
			return 0;
		}

		/* Open the session in promiscuous mode */
		handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
				fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
				return(2);
		}

		printf("wireless gogo\n");
			
		wireless *wl = new wireless(handle);
		wl->airodump();
		
		return(0);
}
