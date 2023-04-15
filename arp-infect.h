#include "utils.h"

// Do ARP table infecting
void ARPInfect(pcap_t* handle, Mac& eth_dmac, Mac& eth_smac, Mac& arp_smac, Ip& arp_sip, Mac& arp_tmac, Ip& arp_tip, bool isRequest);

