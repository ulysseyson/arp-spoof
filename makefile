LDLIBS=-lpcap

all: arp-spoof


main.o: mac.h ip.h ethhdr.h arphdr.h utils.h arp-infect.h main.cpp

arp-infect.o: utils.h arp-infect.h arp-infect.cpp

utils.o : utils.h utils.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ipv4hdr.o: ip.h ipv4hdr.h ipv4hdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

arp-spoof: main.o arp-infect.o utils.o arphdr.o ethhdr.o ipv4hdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
