all:	TCPserver TCPclient


TCPclient:	
	gcc TCPclient.c -o TCPclient

TCPserver:	
	gcc -lpthread TCPserver.c -o TCPserver

clean:
	-rm -f TCPserver
	-rm -f TCPclient