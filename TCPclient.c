//Author:	Ross Gideon
//Date: 	4/30/2018
//Course:	CSCE 3600
//Title:	Major 2 Assignment - Client
//Description:
//*****************
//	This client code is to be run by 2 clients on different machines
//	also connected to the main server. The client will connect to the 
//	server and the user will either choose to send an encrypted message
//	to the other client, or wait for a response. This client code allows 
//	for a single message passed and received(either order) by each client
//	before quitting. To pass a message, the user must choose two co-prime numbers
//	(p and q)to send to the server for validation as a private key. If valid,
//	and the other client is connected, the requesting client will become
//	a "client-server" and pass the encrypted message to the receiving client.
//	The client will then wait to receive a public key from the server, at which
//	point it will connect to the other client now acting as client-server. The receiving client
//	will receive the encrypted message and decrypt it using the public key, completing 
//	the execution. Note that the program listens to both the stdin and server input
//	using the select() function to determine if the client will be the requesting 
//	or receiving client first.
//
//	Interface with server:
//	*************************
//	Send to server: char shared_buff[256] containing "p q" 
//			p and q should be prime, but might not be(user error)
//	
//	Receive from Server: char shared_buff[256] containing either:
//			     	"0"			Other client not connected	
//				"INVALID"		p and q don't work as a key
//				"KEY <num1> <num2>"	num1 and num2 are the public key	
//
//	Receive from other client: char shared_buff[256] 
//				"<encrypted message>"	Req'ing client will send single line of encrypted text
	
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>
 
int encrypt(char*,int,int);
int decrypt(char*,int,int);
void printEncrypted(char*);

int main(int argc,char* argv[])
{
	int sockfd=0,sockfd2=0,serverfd = 0, clientfd=0,client_servfd=0;
	int serv_port, cli_port,cli_size;
	int p,q,n,e,d;
	int key1,key2;
	int clientNo;
	char serv_hostname[50],cli_hostname[50];
	char shared_buff[256];
	char *temp = NULL;
	struct hostent *servaddr, *cliaddr;
	struct sockaddr_in serv_addr;
	struct sockaddr_in cli_addr;
	struct sockaddr_in cli_servaddr;
	struct timeval tv;
	size_t messageLength = 0;
	fd_set rfds;
	int result=0;
	
	
	//Check for proper usage
	if(argc!=5){
		printf("usage: ./TCPclient <svr_host> <svr_port> <rem_ipaddr> <rem_port>\n");
		return 1;
	}

	//Modify command-line args to meet serv_addr format
	serv_port=atoi(argv[2]);
	strcpy(serv_hostname,argv[1]);
	servaddr = gethostbyname(serv_hostname);

	printf("server host name:: %s\n",serv_hostname);
	printf("serv_port 	:: %d\n",serv_port);


	//Modify command-line args to meet cli_addr format
	cli_port=atoi(argv[4]);
	result=inet_pton(AF_INET, argv[3], &cli_addr.sin_addr.s_addr);
		


	printf("Client IP   \t:: %s\n",argv[3]);
	printf("Client Port \t:: %d\n",cli_port);

	//Socket 
	if ((sockfd = socket(AF_INET,SOCK_STREAM,0 )) < 0)
	{
		printf("socket error\n");
		exit(EXIT_FAILURE);
	}
 	
	//Set address variables within serv_addr struct
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(serv_port);
	bcopy((char*)servaddr->h_addr,(char*)&serv_addr.sin_addr.s_addr,servaddr->h_length);
	
	
	//Set address variables within cli_addr struct
	cli_addr.sin_family = AF_INET;
	cli_addr.sin_port = htons(cli_port);
	//bcopy((char*)cliaddr->h_addr,(char*)&cli_addr.sin_addr.s_addr,cliaddr->h_length);
		
		
	//Set attributes for client-server address
	//Use hotn() for Network Byte Order correction
	cli_servaddr.sin_family = AF_INET;    
	cli_servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	cli_servaddr.sin_port = htons(cli_port);

	//Connect to main Server
	if (connect(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr) ) < 0)
	{
		printf("connect error\n");
		exit(EXIT_FAILURE);
	}
	//Receive Client #1 or #2 from server
	recv(sockfd,shared_buff,sizeof(shared_buff),0);
	clientNo = atoi(shared_buff);

	memset(shared_buff, '0', sizeof(shared_buff));
	
	printf("Enter CLIENT %d Data (p and q prime, where p * q > 128): \n",clientNo);
	
	//Clear the fd set
	FD_ZERO(&rfds);
	//Add stdin to fd set
	FD_SET(0,&rfds);
	//Add server fd to set
	FD_SET(sockfd,&rfds);
	
	
	//wait for an i/o event
	select(5,&rfds,NULL,NULL,0);
	
	//detect source of i/o
	if(FD_ISSET(sockfd,&rfds))//Server responded first
	{	
		//Receive keys from server
		recv(sockfd,shared_buff,sizeof(shared_buff),0);
		printf("Received from server :: %s\n",shared_buff);
		sscanf(shared_buff,"%d %d",&d,&n);
		printf("d = %d\n",d);
		printf("n = %d\n",n);

		memset(shared_buff,0,sizeof(shared_buff));

		//Wait 1 second for req'ing client to socket
		sleep(1);

		//Socket to connect to req'ing client
		if ((sockfd2 = socket(AF_INET,SOCK_STREAM,0 )) < 0)
		{
			printf("socket error\n");
			exit(EXIT_FAILURE);
		}
		printf("socketed to connect to other client...\n");
		printf("sockfd2\t:: %d\n",sockfd2);

		//Attempt to connect to req'ing cli
		if (connect(sockfd2,(struct sockaddr*)&cli_addr,sizeof(cli_addr) ) < 0)
		{
			printf("connect error\n");
			exit(EXIT_FAILURE);
		}
		printf("Connected to requesting client...\n");

		//Receive encrypted message from client
		recv(sockfd2,shared_buff,sizeof(shared_buff),0);
		//Print int representation of encrypted message
		printEncrypted(shared_buff);
		
		
		//Decrypt message
		decrypt(shared_buff,n,d);
		printf("Decrypted message\t\t:: %s\n",shared_buff);

		//Close socket used to connect to req'ing client
		close(sockfd2);
		printf("closed sockfd2(to client-server)...\n");

		//Generate new private key, send to server
		do{
			printf("Enter CLIENT %d Data (p and q prime, where p * q > 128): \n",clientNo);
			scanf("%d %d",&key1,&key2);
			sprintf(shared_buff,"%d %d",key1,key2);
			printf("Sent to server\t:: %s\n",shared_buff);
			send(sockfd,shared_buff,sizeof(shared_buff),0);
			memset(shared_buff,0,sizeof(shared_buff));
			recv(sockfd,shared_buff,sizeof(shared_buff),0);

			printf("Received from server\t:: %s\n",shared_buff);
			

			//Server responds with 0 exit
			if(strcmp(shared_buff,"0")==0)
			{
				printf("Other client disconnected\n");
				printf("Message passing disabled\n");
			}
	
			if(strcmp(shared_buff,"INVALID")==0)
			{
				printf("SERVER Message: INVALID (not prime)");

			}
		
		}while(strcmp(shared_buff,"INVALID")==0);
		

			//Store new p and q, zero temporary key inputs
			p = key1;
			q = key2;
			key1 = 0;
			key2 = 0;

			//Get e and n from buffer		
			sscanf(shared_buff, "%d %d", &e, &n);
			printf("e = %d\n",e);
			printf("n = %d\n",n);

			//establish socket to become client-server
			if ((client_servfd = socket(AF_INET,SOCK_STREAM,0 )) == -1)
			{
				printf("socket error\n");
				exit(EXIT_FAILURE);
			}
			printf("Client-server socketed...\n");
			printf("client-server fd :: %d\n",client_servfd);		

			//Bind client-server address to socket
			if (bind(client_servfd ,(struct sockaddr*)&cli_servaddr,sizeof(cli_servaddr)) == -1)
			{
				printf("bind error\n");
				exit(EXIT_FAILURE);
			}
			
			//Only accept a single client connection
			if (listen(client_servfd ,1) == -1)
			{
				printf("listen error\n");
				exit(EXIT_FAILURE);
			}

			//Accept incoming connection from receiving client, store fd in clientfd
	
			sleep(1);
			do{	
				printf("Accepting..\n");
				clientfd = accept(client_servfd, (struct sockaddr*)&cli_addr, &cli_size);
				
				if(clientfd < 0)
				{	
					printf("accept error\n");
					exit(EXIT_FAILURE);
				}					
			}while(clientfd < 0);	
			printf("Accepted connection from Client 1...\n");
			printf("Client 1 fd\t:: %d\n",clientfd);			

			while(getchar()!='\n');
				;

			//Get message to be encrypted
			printf("Enter plaintext message\t:: ");
			scanf("%[^\n]s", shared_buff);
					

			//encrypt message and resend
			encrypt(shared_buff,n,e);
			send(clientfd,shared_buff,sizeof(shared_buff),0);		

			//close socket
			close(client_servfd);
	}
	


	//Client 1 Process Block
	else if(FD_ISSET(0,&rfds))
	{	
		do{
			scanf("%d %d",&key1,&key2);
			sprintf(shared_buff,"%d %d",key1,key2);
			printf("Sent to server :: %s\n",shared_buff);
			send(sockfd,shared_buff,sizeof(shared_buff),0);
			memset(shared_buff,0,sizeof(shared_buff));
			recv(sockfd,shared_buff,sizeof(shared_buff),0);

			printf("Received from server :: %s\n",shared_buff);
			

			//Server responds with 0 exit
			if(strcmp(shared_buff,"0")==0)
			{
				printf("Other client disconnected\n");
				printf("Message passing disabled\n");
			}
	
			if(strcmp(shared_buff,"INVALID")==0)
			{
				printf("SERVER Message: INVALID (not prime)");

			}
		
		}while(strcmp(shared_buff,"INVALID")==0);
		
			

			//Store new p and q, zero temporary key inputs
			p = key1;
			q = key2;
			key1 = 0;
			key2 = 0;

			//Get e and n from buffer		
			sscanf(shared_buff, "%d %d", &e, &n);
			printf("e = %d\n",e);
			printf("n = %d\n",n);

			//establish socket to become client-server
			if ((client_servfd = socket(AF_INET,SOCK_STREAM,0 )) == -1)
			{
				printf("socket error\n");
				exit(EXIT_FAILURE);
			}
			printf("Client-server socketed...\n");
			printf("client_servfd = %d\n",client_servfd);		

			if (bind(client_servfd ,(struct sockaddr*)&cli_servaddr,sizeof(cli_servaddr)) == -1)
			{
				printf("bind error\n");
				exit(EXIT_FAILURE);
			}

			//Can only accept 1 connection
			if (listen(client_servfd ,1) == -1)
			{
				printf("listen error\n");
				exit(EXIT_FAILURE);
			}

			/*
			if ((clientfd = accept(client_servfd,(struct sockaddr*)&cli_addr,&cli_size)) == -1)
			{
				printf("accept error\n");
				//exit(EXIT_FAILURE);
			}
			*/
			sleep(1);
			do{	
				printf("Accepting..\n");
				clientfd = accept(client_servfd, (struct sockaddr*)&cli_addr, &cli_size);
				if(clientfd < 0)
					printf("accept error\n");
			}
			while(clientfd < 0);
			printf("Accepted connection from Client 2...\n");
			printf("Client 2 fd\t:: %d\n",clientfd);

			while(getchar()!='\n');
				;

			//Get message to be encrypted
			printf("Enter plaintext message: ");
			 scanf("%[^\n]s", shared_buff);
				
			//encrypt message and resend
			encrypt(shared_buff,n,e);
			send(clientfd,shared_buff,sizeof(shared_buff),0);
	
			//close socket
			close(client_servfd);


			//Receive keys from server
			recv(sockfd,shared_buff,sizeof(shared_buff),0);
			sscanf(shared_buff,"%d %d",&d,&n);
			printf("d = %d\n",d);
			printf("n = %d\n",n);

			memset(shared_buff,0,sizeof(shared_buff));
			
			//Wait 1 second for req'ing client to socket
			sleep(1);
			
			//Socket to connect to req'ing client
			if ((sockfd2 = socket(AF_INET,SOCK_STREAM,0 )) < 0)
			{
				printf("socket error\n");
				exit(EXIT_FAILURE);
			}

			//Connect to req'ing client
			if (connect(sockfd2,(struct sockaddr*)&cli_addr,sizeof(cli_addr) ) < 0)
			{
				printf("connect error\n");
				exit(EXIT_FAILURE);
			}

			//Receive encrypted message from req'ing client
			recv(sockfd2,shared_buff,sizeof(shared_buff),0);
			printEncrypted(shared_buff);			

			//Decrypt message
			decrypt(shared_buff,n,d);
			printf("Decrypted message\t\t:: %s\n",shared_buff);
		
			close(sockfd2);			
	}	
	close(sockfd);
	printf("Client messages sent and received. Terminating...\n");

	return 0;
}

int encrypt(char* buffer, int n, int e)
{
	int i, j, m;
	for(i = 0; i < strlen(buffer); i++){
		if(isspace(buffer[i])){continue;}
		m = buffer[i];
		for(j = 0; j < (e - 1); j++){
			m = (m * buffer[i]) % n;
		}
		buffer[i] = m;
	}
	return 0;
}
int decrypt(char* buffer, int n, int d)
{
	int i, j, m;
	for(i = 0; i < strlen(buffer); i++){
		if(isspace(buffer[i])){continue;}
		m = buffer[i];
		for(j = 0; j < (d - 1); j++){
			m = (m * buffer[i]) % n;
		}
		buffer[i] = m;
	}
	return 0;
}

void printEncrypted(char* shared_buff)
{
	int i=0;
	
	printf("Received from client-server\t:: ");
	
	for(i=0;shared_buff[i]!='\0';i++)
	{
		printf("%d ",shared_buff[i]);
	}
	printf("\n");
}



