#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include <net/ethernet.h>

#define PROMISC 1			/* Promiscuos mode set for pcap_open_live */
#define READ_TIME_OUT 1000	/* read time out for pcap_open_live */
#define ETHER_ADDR_LEN	6	/* Ethernet addresses are 6 bytes */
#define SIZE_ETHERNET 14	/* ethernet headers are always exactly 14 bytes */

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; 				/* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;			/* version << 4 | header length >> 2 */
	u_char ip_tos;			/* type of service */
	u_short ip_len;			/* total length */
	u_short ip_id;			/* identification */
	u_short ip_off;			/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;			/* time to live */
	u_char ip_p;			/* protocol */
	u_short ip_sum;			/* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/* UDP header */
struct sniff_udp {
	u_short uh_sport;	/* source port */
	u_short uh_dport;	/* destination port */
	u_short uh_len;
	u_short uh_sum;		/* checksum */
};

struct sniff_icmp {
	unsigned char icmph_type;	/* message type */
	unsigned char icmph_code;	/* significant when sending error msg */
	u_short icmph_chksum;		/* checksum for header and data */
	u_short icmph_ident;		/* idesntifier for matching requests/replies */
	u_short icmph_seqnum;		/* seq no to aid matching requests/replies */
};


/*
 * Reference: http://www.tcpdump.org/pcap.html
 * Above link (shared on Piazza) has been used as a
 * sample reference for this homework
 */

/*
 * print data in rows of 16 bytes: offset hex ascii
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {
	int i;
	int gap;
	const u_char *ch;

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");
}


/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len) {
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
}


/* The callback function for pcap_loop */
void got_packet(char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;	/* The ethernet header */
	const struct sniff_ip *ip;		/* The IP header */
	const struct sniff_tcp *tcp;	/* The TCP header */
	const struct sniff_udp *udp;	/* The UDP header */
	const struct sniff_icmp *icmp;	/* The ICMP header */

	const char *payload;		/* Packet payload */
	int size_ip;				/* size of ip packet */
	int size_tcp;				/* size of tcp packet */
	int size_udp = 8;			/* size of udp packet */
	int size_icmp = 8;			/* size of icmp packet */
	int size_payload;			/* size of payload */
	int sport, dport;			/* src/dest port for tcp/udp */
	int proto_tcp = 0;			/* flag to mark tcp protocol */
	int proto_udp = 0;			/* flag to mark upp protocol */
	int proto_icmp = 0;			/* flag to mark icmp protocol */
	int epoch_time;				/* for calculating time for packet */
	time_t epoch_time_as_time_t;
	struct tm * timeinfo;
	char *protocol;				/* string to hold protocol & print later */
	char payload_str[size_payload + 1]; /* string to hold payload */
	char *ether_type;			/* string to hold ether type */

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		printf("Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	switch (ip->ip_p) {
	case IPPROTO_TCP:
		/* define/compute tcp header */
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp) * 4;
		if (size_tcp < 20) {
			printf("Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		protocol = "Protocol: TCP";
		/* define/compute tcp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		/* compute tcp payload (segment) size */
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
		sport = ntohs(tcp->th_sport);
		dport = ntohs(tcp->th_dport);
		proto_tcp = 1;
		break;
	case IPPROTO_UDP:
		/* define/compute udp header */
		udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
		/* define/compute udp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
		/* compute udp payload (segment) size */
		size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
		protocol = "Protocol: UDP";
		sport = ntohs(udp->uh_sport);
		dport = ntohs(udp->uh_dport);
		proto_udp = 1;
		break;
	case IPPROTO_ICMP:
		/* define/compute icmp header */
		icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
		/* define/compute icmp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
		/* compute icmp payload (segment) size */
		size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
		protocol = "Protocol: ICMP";
		proto_icmp = 1;
		break;
	default:
		protocol = "Protocol: OTHER";
		break;
	}

	/* don't do anything if string not present in payload */
	if (args != NULL && strstr(payload, args) == NULL) {
		goto end;
	}

	/* print the information */
	epoch_time = header->ts.tv_sec;
	epoch_time_as_time_t = epoch_time;
	timeinfo = localtime(&epoch_time_as_time_t);
	printf("\nTimestamp: %s", asctime(timeinfo));
	printf("Source MAC Address: %s\n", 
		ether_ntoa((const struct ether_addr *)&ethernet->ether_shost));
	printf("Destination MAC Address: %s\n", 
		ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost));
	printf("Ether Type: 0x%x\n", ntohs(ethernet->ether_type));
	printf("Packet Length: %d\n", header->len);
	printf("Payload Size: %d\n", size_payload);
	printf("Source IP: %s\n", inet_ntoa(ip->ip_src));
	printf("Destination IP: %s\n", inet_ntoa(ip->ip_dst));
	printf("%s\n", protocol);
	/* print protocol specific data */
	if (proto_tcp || proto_udp) {
		/* print data common to both tcp and udp */
		printf("Source port: %d\n", sport);
		printf("Destination port: %d\n", dport);
		/* print data specific to tcp */
		if (proto_tcp) {
			/* print the tcp flag for the packet */
			printf("TCP Flags: ");
			if (tcp->th_flags & TH_FIN) {
				printf("TH_FIN ");
			}
			if (tcp->th_flags & TH_SYN) {
				printf("TH_SYN ");
			}
			if (tcp->th_flags & TH_RST) {
				printf("TH_RST ");
			}
			if (tcp->th_flags & TH_ACK) {
				printf("TH_ACK ");
			}
			if (tcp->th_flags & TH_URG) {
				printf("TH_URG ");
			}
			if (tcp->th_flags & TH_ECE) {
				printf("TH_ECE ");
			}
			if (tcp->th_flags & TH_CWR) {
				printf("TH_CWR ");
			}
			printf("\n");
		}
	} else if (proto_icmp) {	/* print data specific to icmp */
		printf("ICMP Message Type: %u\n", icmp->icmph_type);
	} else {	/* print raw payload for unknown protocol */
		printf("Raw Payload for unknown protocol: %s\n", payload);
		printf("\n\n#################### NEXT PACKET ####################\n");
		goto end;
	}

	/* print payload if present */
	if (size_payload > 0) {
		printf("\nPayload:\n");
		print_payload(payload, size_payload);
	}

	/* print marker for the next packet */
	printf("\n\n#################### NEXT PACKET ####################\n");
end: ;
}


int main(int argc, char *argv[])
{
	char *dev = NULL;				/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
	struct bpf_program fp;			/* The compiled filter expression */
	char *bpf_filter_exp;			/* The filter expression */
	bpf_u_int32 net;				/* The IP of our sniffing device */
	bpf_u_int32 mask;				/* The netmask of our sniffing device */
	pcap_t *handle;					/* packet capture handle */
	int interface_provided = 0;		/* flag to mark interface option */
	int read_file = 0;				/* flag to mark read option */
	int filter_string_found = 0;	/* flag to mark interface string filter */
	int bpf_filter = 0;				/* flag to mark bpf_filter expression */
	int option = 0;					/* for switching on getopt */
	char *filter_str = NULL;		/* filter string */
	char *file_name;				/* filename for read option */

	/* Parse the command line arguments */
	while ((option = getopt(argc, argv, "i:r:s:h")) != -1) {
		switch (option) {
		case 'i':
			if (interface_provided) {
				printf("You should provide only one device. Multiple devices "
					"are not supported.\n");
				exit(EXIT_FAILURE);
			}
			if (read_file) {
				printf("You should not provide file and device together.\n");
				exit(EXIT_FAILURE);
			}
			dev = optarg;
			interface_provided = 1;
			break;
		case 'r':
			if (read_file) {
				printf("You should provide only one file. Multiple files "
					"are not supported.\n");
				exit(EXIT_FAILURE);
			}
			if (interface_provided) {
				printf("You should not provide file and device together.\n");
				exit(EXIT_FAILURE);
			}
			file_name = optarg;
			read_file = 1;
			break;
		case 's':
			if (filter_string_found) {
				printf("If you enter more than one filter options, "
					"payload will be filtered based on the last expression.\n");
			}
			filter_string_found = 1;
			filter_str = optarg;
			break;
		case 'h':
			printf("help: mydump [-i interface] [-r file] [-s string] "
			       "expression\n-i  Listen on network device <interface> "
			       "(e.g., eth0). If not specified, mydump selects the default "
			       "interface to listen on.\n-r  Read packets from <file>\n-s  "
			       "Keep only packets that contain <string> in their payload."
			       "\n<expression> is a BPF filter that specifies which packets "
			       "will be dumped. If no filter is given, all packets seen on "
			       "the interface (or contained in the trace) will be dumped. "
			       "Otherwise, only packets matching <expression> will be "
			       "dumped.\n");
			exit(0);
			break;
		default:
			printf("unknown option or missing argument! Exiting.\n");
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		bpf_filter_exp = argv[optind];
		bpf_filter = 1;
	}

	/* if interface not provided by user, set through pcap library */
	if (interface_provided != 1) {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * get IPv4 network numbers and corresponding network mask
	 * (the network number is the IPv4 address ANDed with the network mask
	 * so it contains only the network part of the address).
	 * This was essential because we needed to know the network mask
	 * in order to apply the filter
	 */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	/*
	 * create handle for the file provided by user,
	 * or open device to read.
	 */
	if (read_file == 1) {
		handle = pcap_open_offline(file_name, errbuf);   //call pcap library function
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open pcap file %s: %s\n", file_name, errbuf);
			exit(EXIT_FAILURE);
		} else {
			printf("Opened file %s\n\n", file_name);
		}
	} else {
		handle = pcap_open_live(dev, BUFSIZ, PROMISC, READ_TIME_OUT, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
		} else {
			printf("Listening on device: %s\n\n", dev);
		}
	}

	/* fail if the device doesn't supply Ethernet headers */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not "
			"supported\n", dev);
		exit(EXIT_FAILURE);
	}

	/* if user specified am expression, compile and set bpf filter */
	if (bpf_filter) {
		/* compile the program */
		if (pcap_compile(handle, &fp, bpf_filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", bpf_filter_exp,
				pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

		/* apply the filter */
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", bpf_filter_exp,
				pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}

	/* set our callback function with infinite pcap_loop */
	pcap_loop(handle, -1, got_packet, filter_str);

	/* clean up */
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;
}
