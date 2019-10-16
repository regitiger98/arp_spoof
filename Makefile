all: send_arp

send_arp: main.o arp.o
	g++ -o send_arp main.o arp.o -lpcap

arp.o: arp.cpp arp.h
	g++ -c -o arp.o arp.cpp

main.o: main.cpp arp.h
	g++ -c -o main.o main.cpp

clean:
	rm -f send_arp *.o
