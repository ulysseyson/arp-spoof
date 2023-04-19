#include "utils.h"

// Do ARP table infecting when detect broadcast packet
void ARPInfectDetectPacket(
    pcap_t* handle,
    Mac& attacker_mac,
    Ip& attacker_ip,
    Mac& sender_mac,
    Ip& sender_ip,
    Ip& target_ip,
    Mac& target_mac);

// Do ARP table infecting for every 5min
void ARPInfectFrequent(
    pcap_t* handle,
    Mac& attacker_mac,
    Ip& attacker_ip,
    Mac& sender_mac,
    Ip& sender_ip,
    Ip& target_ip);

// Do sending relay packet to target(gateway)
void ARPRelay(
    pcap_t* handle,
    Mac& attacker_mac,
    Ip& attacker_ip,
    Mac& sender_mac,
    Ip& sender_ip,
    Ip& target_ip,
    Mac& target_mac);