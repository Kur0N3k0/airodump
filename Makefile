all: allcomp
	
allcomp: wireless
	g++ -o pcap pcap.cpp wireless.o -lpcap -std=c++11 -D__RTDETAIL__

wireless:
	g++ -c wireless.cpp -lpcap -std=c++11

clean:
	rm -rf *.o
