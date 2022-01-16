#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <pcap.h>
#include <time.h>

int tcpPackets=0;
int udpPackets=0;
int totalPackets=0;
int tcpBytes=0;
int udpBytes=0;
struct sockaddr_in source, dest;
int flows=0;
int tcpFlows=0;
int udpFlows=0;

typedef struct network_flow{
	char *sourceIPv4;
	int sourcePort;
	char *destinationIPv4;
	int destinationPort;
	int protocol;

}NFL;

NFL* newFlow;

void usage(void){
	printf(
		"\n"
		"Usage:\n"
		"Options:\n"
		" -r Packet capture file name (e.g. test.pcap)\n "
		" -h helps message \n\n "
		);
	exit(EXIT_FAILURE);
}

void countflows(char* sourceIPv4,int sourcePort,char* destinationIPv4,int destinationPort,int protocol){
	if(flows == 0){
		newFlow = (NFL*)malloc(sizeof(NFL));
		flows++;
		if(protocol ==6){
		tcpFlows++;
	}
	else{
		udpFlows++;
	}
	newFlow[0].sourceIPv4 = (char *)malloc(sizeof(char)*(strlen(sourceIPv4)+1));
	newFlow[0].destinationIPv4 = (char *)malloc(sizeof(char)*(strlen(destinationIPv4)+1));
	newFlow =(NFL *)realloc(newFlow,flows*sizeof(NFL));
	strcpy(newFlow[0].sourceIPv4,sourceIPv4);
	newFlow[0].sourcePort=sourcePort;
	strcpy(newFlow[0].destinationIPv4,destinationIPv4);
	newFlow[0].destinationPort=destinationPort;
	newFlow[0].protocol=protocol;
	}
	else{
	int counter = flows;
	flows++;
	if(protocol ==6){
		tcpFlows++;
	}
	else{
		udpFlows++;
	}
	newFlow =(NFL *)realloc(newFlow,flows*sizeof(NFL));
	newFlow[counter].sourceIPv4 = (char *)malloc(sizeof(char)*(strlen(sourceIPv4)+1));
	newFlow[counter].destinationIPv4 = (char *)malloc(sizeof(char)*(strlen(destinationIPv4)+1));
	strcpy(newFlow[counter].sourceIPv4,sourceIPv4);
	newFlow[counter].sourcePort=sourcePort;
	strcpy(newFlow[counter].destinationIPv4,destinationIPv4);
	newFlow[counter].destinationPort=destinationPort;
	newFlow[counter].protocol=protocol;
}



}

void print_tcp(const u_char *buffer,int size){

	unsigned short ipheaderlength;

	struct iphdr *ipheader = (struct iphdr *)(buffer  + sizeof(struct ethhdr) );
	ipheaderlength =ipheader->ihl*4;

	struct tcphdr *tcpheader=(struct tcphdr*)(buffer + ipheaderlength + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + ipheaderlength + tcpheader->doff*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ipheader->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ipheader->daddr;


	printf("\nTCP Packet\n");
	printf(" -Source IP      : %s\n",inet_ntoa(source.sin_addr));
	printf(" -Destination IP      : %s\n",inet_ntoa(dest.sin_addr));
	printf(" -Source port      : %d\n",ntohs(tcpheader->source));
	printf(" -Destination port      : %d\n",ntohs(tcpheader->dest));
	printf(" -Protocol     : %d\n",(unsigned int)ipheader->protocol);
	printf(" -Header length: %d bytes \n",(unsigned int)tcpheader->doff*4);
	printf(" -Payload length: %d bytes \n\n",size-header_size);

	countflows(inet_ntoa(source.sin_addr),ntohs(tcpheader->source),inet_ntoa(dest.sin_addr),ntohs(tcpheader->dest),(unsigned int)ipheader->protocol);



}

void print_udp(const u_char *buffer,int size){

	unsigned short ipheaderlength;

	struct iphdr *ipheader = (struct iphdr *)(buffer  + sizeof(struct ethhdr) );
	ipheaderlength =ipheader->ihl*4;

	struct udphdr *udpheader=(struct udphdr*)(buffer + ipheaderlength + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + ipheaderlength + sizeof udpheader;


	printf("\nUDP Packet\n");
	printf(" -Source IP      : %s\n",inet_ntoa(source.sin_addr));
	printf(" -Destination IP      : %s\n",inet_ntoa(dest.sin_addr));
	printf(" -Source port      : %d\n",ntohs(udpheader->source));
	printf(" -Destination port      : %d\n",ntohs(udpheader->dest));
	printf(" -Protocol     : %d\n",(unsigned int)ipheader->protocol);
	printf(" -Header length: %ld bytes \n",sizeof(udpheader));
	printf(" -Payload length: %d bytes \n\n",size-header_size);

	countflows(inet_ntoa(source.sin_addr),ntohs(udpheader->source),inet_ntoa(dest.sin_addr),ntohs(udpheader->dest),(unsigned int)ipheader->protocol);


}



void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	++totalPackets;
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	switch(iph->protocol){
		case 6:
			++tcpPackets;
			tcpBytes+=size;
			print_tcp(buffer,size);
			break;
		case 17:
			++udpPackets;
			udpBytes+=size;
			print_udp(buffer,size);
			break;
		default:
			break;
	}

}



void printStatistics(){
	printf("\nTotal number of network flows captured: %d\n",flows);
	printf("Total number of TCP network flows captured: %d\n",tcpFlows);
	printf("Total number of  UDP network flows captured: %d\n",udpFlows);
    printf("Total number of packets received: %d\n", totalPackets);
	printf("Total number of TCP packets received: %d\n", tcpPackets);
	printf("Total number of UDP packets receive: %d\n", udpPackets);
	printf("Total bytes of TCP packets received: %d\n", tcpBytes);
	printf("Total bytes of UDP packets received: %d\n", udpBytes);
}

int main(int argc, char *argv[]){

	int opt;
	pcap_t* pcapFile;
	char errbuf[PCAP_ERRBUF_SIZE];

	

	while ((opt = getopt(argc, argv, "h:r:")) != -1) {
		switch (opt) {
		case 'r':
			pcapFile = pcap_open_offline(strdup(optarg),errbuf);	
        	pcap_loop(pcapFile, -1, process_packet, NULL);
			break;
	
		case 'h':
		default:
			usage();
		}
	}

	printStatistics();
	pcap_close(pcapFile);
	return 0;	
}