// ========================================================================
// Name:        Mitchell Buehler (Major 2 Group 14)
// Course:		CSCE 3600
// Date:		May 3, 2018
// Title:		Major Assignment 2 - Server
// Version:		1.2 (Final)
// Description: Socket Server Component to Which Client Programs Connect
//------------------------------------------------------------------------
//			Example Output to/Expected Input from socket buffer 
//			During a Message Exchange Cycle between two Clients:
//------------------------------------------------------------------------
//			
//			Receive Primes from Client 1: "<int p> <int q>" 
//			(Server will close thread and wait for new connection to
//			continue if client sends "0" at this point)
//			If P and Q are valid
//				Send Private Key to Client 1: "<int e> <int n>"
//			Else
//				Send to Client 1: "INVALID"
//				Loop back and receive new input, repeating until valid
//			Send Public Key to Client 2: "<int d> <int n>" 
//
//			<wait during message exchange>
//
//			Receive Primes from Client 2: "<int p> <int q>"
//			(Server will close thread and wait for new connection to
//			continue if client sends "0" at this point)
//			If P and Q are valid
//				Send Private Key to Client 2: "<int e> <int n>"
//			Else
//				Send to Client 2: "INVALID"
//				Loop back and receive new input, repeating until valid
//			Send Public Key to Client 1: "<int d> <int n>" 
//
//			<wait during message exchange>
//
//			Disconnect Both Clients and Repeat
//
//-------------------------------------------------------------------------
// Usage:	./major2svr <port>
//-------------------------------------------------------------------------
//
//			KNOWN ISSUES:
//
//			- If a client disconnects before cycle is complete, it will be rejected
//			as if it is a third client
//			- Server exits after one message exchange cycle
//
// ========================================================================

#include <stdio.h>
#include <sys/types.h> 
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>

struct cryptoData {
	int p;
	int q;
	int n;
	int e;
	int phi;
	int d;
};

pthread_mutex_t svrMutex = PTHREAD_MUTEX_INITIALIZER; /* Mutex for handling client rejection thread */
pthread_mutex_t cliMutex = PTHREAD_MUTEX_INITIALIZER; /* Mutex for synchronizing connected client threads */
pthread_cond_t rejectClients = PTHREAD_COND_INITIALIZER; /* Othread Condition Variable to wake client connection rejection thread */

struct cryptoData clientData; /* Global data struct for access in client threads */
bool client[2]; /* Store thread status of both clients to handle reconnecting when a client disconnects */
bool connection[2]; /* Store connection status of both clients to handle reconnecting when a client disconnects */
sem_t cliSem; /* Semaphore to only allow 2 client threads at once */
struct sockaddr_in svrAddr; /* Server Address Struct */
int svrSock; /* Listen Socket */
int flowCtrl = 0;
int flowCtrl2 = 0;


void *client_handler(void *clientNum); /* Function for Client Handler Threads */
void *reject_client(void *arg); /* Function for Extra Client Refusal Handler */
int cryptoFunction(int p, int q, int key[]);
int gcd(int a, int b);



int main(int argc, char *argv[])
{
	client[0] = client[1] = false; /* Initialize Client Status' as False */
    connection[0] = connection[1] = false;
	int portNum; /* Port Number */
	int cliNum[3] = { 1, 2, 0 }; /* Client Numbers to pass when creating Threads */
	pthread_t cliArr[3]; /* pthreads for both clients and extra client refusal handler */
	
	
	/* Verify Arguments */
	if (argc < 2) {
		fprintf(stderr, "Usage: ./major2svr <portno>\n");
		exit(1);
	}
	portNum = atoi(argv[1]);
	if (portNum < 0 || portNum > 65535) {
		fprintf(stderr, "Error: Invalid port number.\n");
		exit(1);
	}
	
	
	/* Create Socket */
	if ((svrSock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Error creating socket\n");
		exit(1);
	}
	
	/* Create address of server */
	svrAddr.sin_family = AF_INET;
	svrAddr.sin_addr.s_addr = INADDR_ANY;
	svrAddr.sin_port = htons(portNum);
		
	/* Bind socket to server address */
	if (bind(svrSock, (struct sockaddr *) &svrAddr, sizeof(svrAddr)) < 0) {
		perror("Error binding Socket\n");
		exit(1);
	}
	
	/* Initialize Semaphore, Mutexes, and Condition Var*/
	if (sem_init(&cliSem, 0, 2) < 0) {
		perror("Error initializing Semaphore\n");
		exit(1);
	}
	if (pthread_mutex_init(&svrMutex, NULL) < 0) {
		perror("Error initializing Mutex\n");
		exit(1);
	}
	if (pthread_mutex_init(&cliMutex, NULL) < 0) {
		perror("Error initializing Mutex\n");
		exit(1);
	}
	if (pthread_cond_init(&rejectClients, NULL) < 0) {
		perror("Error initializing Condition Variable\n");
		exit(1);
	}

	
	/* Listen For Connections */
	if (listen(svrSock, 5) < 0) {
		perror("Error initializing Connection Listener.\n");
		exit(1);
	}
	printf("Waiting for incoming connections...\n");
	
	/* Create Threads to handle Incoming Connections */
	while (1) {
		/* Create 1st Client Thread */
		if (!client[0]) {
			pthread_create(&cliArr[1], NULL, client_handler, (void *) &cliNum[0]);
			pthread_detach(cliArr[1]);
			client[0] = true;
		}
		/* Create 2nd Client Thread once 1st Client Connected */
		else if(client[0] && !client[1]) {
			pthread_create(&cliArr[2], NULL, client_handler, (void *) &cliNum[1]);
			pthread_detach(cliArr[2]);
			client[1] = true;
		}
		/* Create thread to reject additional clients */
		else {
			pthread_create(&cliArr[0], NULL, reject_client, (void *) &cliNum[2]);
			pthread_join(cliArr[0], NULL); /* Wait until thread terminates to continue next iteration of loop */
		}
	}
	return EXIT_SUCCESS;
}

void *client_handler(void *clientNum) {
	struct sockaddr_in cliAddr;
	int cliLen = sizeof(cliAddr);
	int cliSock;
	int bytesRead;
	char buf[256];
	bool clientExit = false, clientFinished = false, inputValid = false;
	int keyResults[4];
		

	/* Decrement Semaphore on Thread Creation */
	sem_wait(&cliSem);
	
	
	if ((cliSock = accept(svrSock, (struct sockaddr *) &cliAddr, &cliLen)) < 0) {
		perror("Failed to accept Connection\n");
		pthread_exit(clientNum);
	}
    
	printf("Connection to Client %d Successful\n", *((int*)(clientNum)));
	sprintf(buf,"%d",*((int*)(clientNum)));
	send(cliSock,buf,sizeof(buf),0);
	memset(buf,0,sizeof(buf));	
    connection[(*((int*)(clientNum))) - 1] = true;
    
	/* Handle Client Connection and Processes */
	while (1) {
		/* Process Loop for Client 1 */
		if (*((int*)(clientNum)) == 1) {
			/* If First Loop, Request for P and Q Data */
			if (flowCtrl == 0) {
				/* Lock Mutex, receive P and Q, verify they're valid, then complete remaining calculations */
				pthread_mutex_lock(&cliMutex);				

				/* Wait until Client 2 is Connected before Starting */
				while (connection[1] == false)
					sleep(1);

				do {	
					bytesRead = recv(cliSock, buf, sizeof(buf), 0);
					if (bytesRead < 1) {
						clientExit = true;
						pthread_mutex_unlock(&cliMutex);
						
					}
					else if (strncmp(buf, "0", 1) == 0) {
						clientExit = true;
						pthread_mutex_unlock(&cliMutex);
					
					}
					else {
						sscanf(buf, "%d %d", &clientData.p, &clientData.q);
						inputValid = cryptoFunction(clientData.p, clientData.q,keyResults); 
												
						if (!inputValid) {
							/* If p and/or q are invalid, send message to Client */
							bzero(buf, 256);
							sprintf(buf, "INVALID");
							send(cliSock, buf, sizeof(buf), 0);
							clientData.p = 0;
							clientData.q = 0;
						}
						else {
							/* Use p and q to calculate e, n, d, and phi, print result */
							clientData.n 	= keyResults[0];						
							clientData.d 	= keyResults[1];
							clientData.e 	= keyResults[2];
							clientData.phi	= keyResults[3];						

							printf("p=%d q=%d n=%d e=%d phi=%d d=%d\n", clientData.p, clientData.q, clientData.n, clientData.e, clientData.phi, clientData.d);
												
							/* Move e and n to buffer, send private key to client 1, unlock mutex */
							bzero(buf, 256);
							sprintf(buf, "%d %d", clientData.e, clientData.n);
							send(cliSock, buf, sizeof(buf), 0);
							pthread_mutex_unlock(&cliMutex);
				
							/* Increment Loop Control Variable to Proceed to Next Loop */
							flowCtrl++;
						}
					}
				} while (!inputValid);
			}
			
			/* If Second Loop, Wait for Mutex then Send Public Key from Client 2 */
			else if(flowCtrl == 1) {
				while(flowCtrl2!=1)
					sleep(1);

				pthread_mutex_lock(&cliMutex);
				bzero(buf, 256);
				printf("Sending Client 2 Public Key to Client 1\n");
				sprintf(buf, "%d %d", clientData.d, clientData.n);
				send(cliSock, buf, sizeof(buf), 0);
				pthread_mutex_unlock(&cliMutex);
				
				client[0] = false;
				clientFinished = true;
				clientData.d = clientData.e = clientData.n = clientData.p = clientData.phi = clientData.q = 0;
			}
		}
		




		/* Process Loop for Client 2 */
		else if(*((int*)(clientNum)) == 2) {
		
			/* Send signal to client rejection thread to begin processing */
			pthread_mutex_lock(&svrMutex);
			pthread_cond_signal(&rejectClients);
			pthread_mutex_unlock(&svrMutex);
			

			/* If First Loop, Wait for Mutex then Send Public Key from Client 1 */
			if (flowCtrl2 == 0) {
				pthread_mutex_lock(&cliMutex);
				bzero(buf, 256);
				printf("Sending Client 1 Public Key to Client 2\n");
				sprintf(buf, "%d %d", clientData.d, clientData.n);
				send(cliSock, buf, sizeof(buf), 0);
				clientData.d = clientData.e = clientData.n = clientData.p = clientData.phi = clientData.q = 0;
				pthread_mutex_unlock(&cliMutex);
				
				/* Increment Loop Control Variable & Clear clientData struct to Proceed to Next Loop */
				flowCtrl2++;
				
			}
			/* If Second Loop, Request for P and Q Data */
			else if(flowCtrl2 == 1) {
				/* Lock Mutex, receive P and Q, verify they're valid, then complete remaining calculations */
				pthread_mutex_lock(&cliMutex);
				
				do {
					bytesRead = recv(cliSock, buf, sizeof(buf), 0);
					if (bytesRead < 1) {
						clientExit = true;
						pthread_mutex_unlock(&cliMutex);
					}
					else if (strncmp(buf, "0", 1) == 0) {
						clientExit = true;
						pthread_mutex_unlock(&cliMutex);
					}
					else {
						sscanf(buf, "%d %d", &clientData.p, &clientData.q);
						inputValid = cryptoFunction(clientData.p, clientData.q,keyResults);
						
						if (!inputValid) {
							/* If p and/or q are invalid, send message to Client */
							bzero(buf, 256);
							sprintf(buf, "INVALID");
							send(cliSock, buf, sizeof(buf), 0);
							clientData.p = 0;
							clientData.q = 0;
						}
						else {
							/* Use p and q to calculate e, n, d, and phi, print result */
							clientData.n = keyResults[0];						
							clientData.d = keyResults[1];
							clientData.e = keyResults[2];				
		
							printf("p=%d q=%d n=%d e=%d phi=%d d=%d\n", clientData.p, clientData.q, clientData.n, clientData.e, clientData.phi, clientData.d);
					
							/* Move e and n to buffer, send private key to client 2, unlock mutex */
							bzero(buf, 256);
							sprintf(buf, "%d %d", clientData.e, clientData.n);
							send(cliSock, buf, sizeof(buf), 0);
							pthread_mutex_unlock(&cliMutex);

							client[1] = false;
							clientFinished = true;
							sem_post(&cliSem);
						}
					}
				} while (!inputValid);
			}
		}
		
		if (clientExit) {
			/* close socket and increment semaphore */
			close(cliSock);
			sem_post(&cliSem);
		
			/* Resume processing with next client connection, set clientExit back to false */
			cliSock = 0;
			bzero((char *) &cliAddr, sizeof(cliAddr));
			if ((cliSock = accept(svrSock, (struct sockaddr *) &cliAddr, (socklen_t *)(&cliLen))) < 0) {
				perror("Failed to accept Connection\n");
				pthread_exit(clientNum);
			}
			clientExit = false;
		
			/* Send signal to wake thread rejecting additional client connections */
			pthread_mutex_lock(&svrMutex);
			pthread_cond_signal(&rejectClients);
			pthread_mutex_unlock(&svrMutex);
		} 
		
        if(clientFinished){
            /* Exit loop, close socket, exit thread if message exchange complete */
            break;
        }
	}
	
	/* Close socket, increment semaphore, and exit thread after client disconnects */
	close(cliSock);
	sem_post(&cliSem);
	printf("Client %d Disconnected\n", *((int*)(clientNum)));
	pthread_exit(clientNum);
}

void *reject_client(void *arg) {
	
	/* Create Thread to Handle Rejecting Connections, killed by initial thread when signal is received in order to respond more quickly */
	if (*((int *) arg) == 0) {
		/* Create thread, wait until a client disconnects and then kill subthread and exit */
		int rejectThread = 1;
		pthread_t cliReject;
		pthread_create(&cliReject, NULL, reject_client, (void *) &rejectThread);
		pthread_detach(cliReject);
		sem_wait(&cliSem);
		pthread_kill(cliReject, SIGINT);
		pthread_exit(arg);
	}
	else {
		struct sockaddr_in cliAddr;
		int cliLen = sizeof(cliAddr);
		int cliSock;
		
		/* Wait for signal to start rejecting connections */
		pthread_mutex_lock(&svrMutex);
		pthread_cond_wait(&rejectClients, &svrMutex);
		pthread_mutex_unlock(&svrMutex);
		
		/* Loop to reject connections of any additional clients after first two */
		while (1) {
			cliSock = 0;
			bzero((char *) &cliAddr, sizeof(cliAddr));
			if ((cliSock = accept(svrSock, (struct sockaddr *) &cliAddr, (socklen_t *)(&cliLen))) < 0) {
				perror("Failed to accept Connection\n");
				pthread_exit(arg);
			}
	
			/* Send message to Client indicating that there are already two clients connected */
			
            
			fprintf(stderr, "ERROR: Two clients are already connected, refusing connection\n");
			close(cliSock);
		}
	}
}



int cryptoFunction(int p, int q, int key[])
{
	int n = p*q;
	int phi = (p-1)*(q-1);
	int e = 2;
	int d, temp;
	int i = 1;
	if(n < 127){printf("product of p and q must be greater than 127"); return 0;}
	while(e < phi){//find e such that 1 < e < phi
		if(gcd(e, phi) == 1){break;}
		else{e++;}
	}
	while(1){//find d such that 1 < d < phi
		temp = (phi * i) + 1;
		if(temp%e == 0){
			d = temp/e;
			break;
		}
		i++;
	}
	key[0] = n;
	key[1] = d;
	key[2] = e;
	key[3] = phi;
	return 1;

}
int gcd(int a, int b)
{
	int temp;
	while(1){
		temp = a % b;
		if(temp == 0){return b;}
		a = b;
		b = temp;
	}
	return 1;
}





