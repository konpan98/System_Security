gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0

For questions 1 and 2 we use the function pcap_open_offline in order to start reading packets

For questions 3 and 4 we call the pcap_loop function using the callback method process_packets 
There we decode the tcp and udp packets using the protocol number(6 for tcp and 17 for udp)

Questions 5 and 8 with regard the info about the tcp and and udp packets are printed in functions print_tcp and print_udp

Question 9 
Retransmission for the tcp packets can be easily be checked by exploiting the expected acknowledgment sequence.
Because these acks are unique any duplicate we reveive means that the packet is retransmitted

Question 10
In the udp packets we cannot use the acknowledgments as a tool to check the retransmission so it is more difficult to see if the packet
is retransmitted or not 

Question 11
I didnt implements the marking of the packets as "Retransmitted" but the method should be the exact that we desrcribed in question 9


Question 12
All the info that we need for this question are printed by calling the function printStatistics


Useful links 
https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
https://linux.die.net/man/3/pcap
https://www.tcpdump.org/manpages/tcpdump.1.html
