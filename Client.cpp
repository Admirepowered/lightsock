#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <errno.h>
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable : 4996)
#define max(a,b) (((a)>(b))?(a):(b))
#define MAX_HOSTNAME 256
#define DEFAULTPORT   80
#define LISTENPORT   1080
#define DEFLISNUM   50
#define MAXBUFSIZE   20480
#define TIMEOUT    10000
#define HEADLEN    7
char ErrorMsg[] = "Http/1.1 403 Forbidden\r\n\r\n<body><h1>403 Forbidden</h1></body>";
char ConnectionEstablished[] = "HTTP/1.0 200 OK\r\n\r\n";
int LisPort;
char Username[256] = "\0";
char Password[256] = "\0";
char pass[256] = "\0";
char server1[256] = "\0";
int serverport;
struct Socks4Req
{
    BYTE Ver;
    BYTE REP;
    WORD wPort;
    DWORD dwIP;
    BYTE other[1];
};
struct Socks5Req
{
    BYTE Ver;
    BYTE nMethods;
    BYTE Methods[255];
};
struct AuthReq
{
    BYTE Ver;
    BYTE Ulen;
    BYTE UserPass[1024];
};
typedef struct
{
    BYTE Ver;      // Version Number
    BYTE CMD;      // 0x01==TCP CONNECT,0x02==TCP BIND,0x03==UDP ASSOCIATE
    BYTE RSV;
    BYTE ATYP;
    BYTE IP_LEN;
    BYTE szIP;
}Socks5Info;
typedef struct
{
    DWORD dwIP;
    WORD wPort;
}IPandPort;
typedef struct
{
    BYTE Ver;
    BYTE REP;
    BYTE RSV;
    BYTE ATYP;
    IPandPort IPandPort;
}Socks5AnsConn;
typedef struct
{
    BYTE RSV[2];
    BYTE FRAG;
    BYTE ATYP;
    IPandPort IPandPort;
    // BYTE DATA;
}Socks5UDPHead;
struct SocketInfo
{
    SOCKET socks;
    IPandPort IPandPort;
};
typedef struct
{
    SocketInfo Local;
    SocketInfo Client;
    SocketInfo Server;
}Socks5Para;
// End Of Structure
static CRITICAL_SECTION cs;
void TCPTransfer(SOCKET* CSsocket);
void UDPTransfer(Socks5Para* sPara);

BOOL ConnectToRemoteHost(SOCKET* ServerSocket, char* HostName, const WORD RemotePort);
/////////////////////////////////////////////////////
//---------------------------------------------------------------------------

void GetHostNameAndPort(char* ReceiveBuf, int datalen, char* HostName, UINT* RemotePort)
{
    char* fp = ReceiveBuf;
    for (int i = 0; i < datalen && *fp != ':' && *fp != '\0' && *fp != '\r' && *fp != '/'; i++)
    {
        HostName[i] = *fp++;
        if (*fp == ':')
            *RemotePort = atoi(fp + 1);
        else *RemotePort = DEFAULTPORT;
    }
}
void xor1(char* data, int q) {
    int i;
    if (q == 0)for (i = 0; i < strlen(data); i++)data[i] = data[i] ^ pass[1];
    else for (i = 0; i < q; i++)data[i] = data[i] ^ pass[1];
}
//---------------------------------------------------------------------------
char* GetURLRootPoint(char* ReceiveBuf, int DataLen, int* HostNaneLen)
{
    for (int i = 0; i < DataLen; i++)
    {
        if (ReceiveBuf[i] == '/')
        {
            *HostNaneLen = i;
            return &ReceiveBuf[i];
        }
    }
    return NULL;
}
//---------------------------------------------------------------------------
int CheckRequest(char* ReceiveBuf, int* MethodLength)
{
    if (!strcmp(ReceiveBuf, "GET"))
    {
        *MethodLength = 4;
        return 1;
    }
    else if (!strcmp(ReceiveBuf, "HEAD")) //Looks like the same with GET
    {
        *MethodLength = 5;
        return 2;
    }
    else if (!strcmp(ReceiveBuf, "POST"))
    {
        *MethodLength = 5;
        return 3;
    }
    else if (!strcmp(ReceiveBuf, "CONNECT"))
    {
        *MethodLength = 8;
        return 4;
    }
    else
    {
        return 0;
    }
}
int ModifyRequest(char* SenderBuf, char* ReceiveBuf, int DataLen, int MethodLength)
{
    strncpy(SenderBuf, ReceiveBuf, MethodLength);
    int HedLen = 0;
    if (strncmp(ReceiveBuf + MethodLength, "http://", HEADLEN))
        return 0;
    char* Getrootfp = GetURLRootPoint(ReceiveBuf + MethodLength + HEADLEN, DataLen - MethodLength - HEADLEN, &HedLen);
    if (Getrootfp == NULL)
        return 0;
    memcpy(SenderBuf + MethodLength, Getrootfp, DataLen - MethodLength - HEADLEN - HedLen);
    return DataLen - HEADLEN - HedLen;
}
BOOL SendRequest(SOCKET* CSsocket, char* SenderBuf, char* ReceiveBuf, int DataLen)
{
    //CSsocket[0] ClientSocket
    //CSsocket[1] ServerSocket
    DWORD dwThreadID;
    char   HostName[MAX_HOSTNAME] = { 0 };
    char   ReqInfo1[8], ReqInfo2[248];
    UINT   RemotePort = 0;
    static int t = 0;
    EnterCriticalSection(&cs);
    int n = ++t;
    LeaveCriticalSection(&cs);
    int Flag = 0, MethodLength = 0, SendLength = 0;
    Flag = CheckRequest(ReceiveBuf, &MethodLength);
    if (Flag == 0) return 0;
    if (Flag == 1 || Flag == 2 || Flag == 3)
    {
        SendLength = ModifyRequest(SenderBuf, ReceiveBuf, DataLen, MethodLength);
        if (!SendLength)
            return 0;
        GetHostNameAndPort(ReceiveBuf + MethodLength + HEADLEN, DataLen - MethodLength - HEADLEN, HostName, &RemotePort);
        if (!ConnectToRemoteHost(&CSsocket[1], HostName, RemotePort))
            return 0;
        if (send(CSsocket[1], SenderBuf, SendLength, 0) == SOCKET_ERROR)
            return 0;
    }
    else if (Flag == 4)
    {
        GetHostNameAndPort(ReceiveBuf + MethodLength, DataLen - MethodLength, HostName, &RemotePort);
        if (!ConnectToRemoteHost(&CSsocket[1], HostName, RemotePort))
            return 0;
        send(CSsocket[0], ConnectionEstablished, strlen(ConnectionEstablished) + 1, 0);
    }
    if (CSsocket[0] && CSsocket[1])
    {
        //printf("HTTP Proxy request %d OK.\n",n);
        //sscanf(ReceiveBuf,"%s %s",ReqInfo1,ReqInfo2);
        //printf("%s %s\n",ReqInfo1,ReqInfo2);
        HANDLE ThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TCPTransfer, (LPVOID)CSsocket, 0, &dwThreadID);
        if (ThreadHandle != NULL)
        {
            WaitForSingleObject(ThreadHandle, INFINITE);
            //printf("HTTP Proxy request %d Exit.\n",n);
        }
    }
    else
        return 0;
    return 1;
}
/////////////////////////////////////////////////////
int Authentication(SOCKET* CSsocket, char* ReceiveBuf, int DataLen)
{
    Socks5Req* sq;
    char Method[2] = { 0x05,0 };
    sq = (Socks5Req*)ReceiveBuf;
    ///////printf("%d,%d,%d,%d,%d\n",sq->Ver,sq->nMethods,sq->Methods[0],sq->Methods[1],sq->Methods[2]);
    if (sq->Ver != 5)
        return sq->Ver;
    if ((sq->Methods[0] == 0) || (sq->Methods[0] == 2))
    {
        if (strlen(Username) == 0)
            Method[1] = 0x00;
        else
            Method[1] = 0x02;
        if (send(CSsocket[0], Method, 2, 0) == SOCKET_ERROR)
            return 0;
    }
    else
        return 0;
    if (Method[1] == 0x02)
    {
        char USER[256];
        char PASS[256];
        memset(USER, 0, sizeof(USER));
        memset(PASS, 0, sizeof(PASS));
        DataLen = recv(CSsocket[0], ReceiveBuf, MAXBUFSIZE, 0);
        if (DataLen == SOCKET_ERROR || DataLen == 0)
            return 0;
        AuthReq* aq = (AuthReq*)ReceiveBuf;
        if (aq->Ver != 1)
            return 0;
        if ((aq->Ulen != 0) && (aq->Ulen <= 256))
            memcpy(USER, ReceiveBuf + 2, aq->Ulen);
        int PLen = ReceiveBuf[2 + aq->Ulen];
        if ((PLen != 0) && (PLen <= 256))
            memcpy(PASS, ReceiveBuf + 3 + aq->Ulen, PLen);
        //printf("USER %s\nPASS %s\n",USER,PASS);
        //0=login successfully,0xFF=failure;
        if (!strcmp(Username, USER) && !strcmp(Password, PASS))
        {
            ReceiveBuf[1] = 0x00;
            //printf("Socks5 Authentication Passed\n");
        }
        else
        {
            ReceiveBuf[1] = 0xFF;
            //printf("Invalid Password\n");
        }
        if (send(CSsocket[0], ReceiveBuf, 2, 0) == SOCKET_ERROR)
            return 0;
    }
    return 1;
}
char* GetInetIP(char* OutIP)
{
    // Get host adresses
    char addr[16];
    struct hostent* pHost;
    pHost = gethostbyname("");
    for (int i = 0; pHost != NULL && pHost->h_addr_list[i] != NULL; i++)
    {
        OutIP[0] = 0;
        for (int j = 0; j < pHost->h_length; j++)
        {
            if (j > 0) strcat(OutIP, ".");
            sprintf(addr, "%u", (unsigned int)((unsigned char*)pHost->h_addr_list[i])[j]);
            strcat(OutIP, addr);
        }
    }
    return OutIP;
}
char* DNS(char* HostName)
{
    HOSTENT* hostent = NULL;
    IN_ADDR iaddr;
    hostent = gethostbyname(HostName);
    if (hostent == NULL)
    {
        return NULL;
    }
    iaddr = *((LPIN_ADDR)*hostent->h_addr_list);
    return inet_ntoa(iaddr);
}
int GetAddressAndPort(char* ReceiveBuf, int DataLen, int ATYP, char* HostName, WORD* RemotePort)
{
    DWORD Socks5InfoSize = sizeof(Socks5Info);
    DWORD dwIndex = 0;
    Socks4Req* Socks4Request = (Socks4Req*)ReceiveBuf;
    Socks5Info* Socks5Request = (Socks5Info*)ReceiveBuf;
    struct sockaddr_in in;
    if (ATYP == 2) //Socks v4 !!!
    {
        *RemotePort = ntohs(Socks4Request->wPort);
        if (ReceiveBuf[4] != 0x00) //USERID !!
            in.sin_addr.s_addr = Socks4Request->dwIP;
        else
            in.sin_addr.s_addr = inet_addr(DNS((char*)&Socks4Request->other + 1));
        memcpy(HostName, inet_ntoa(in.sin_addr), strlen(inet_ntoa(in.sin_addr)));
        return 1;
    }
    
    if ((Socks5Request->Ver == 5) && (ATYP == 1))
    {
        IPandPort* IPP = (IPandPort*)&Socks5Request->IP_LEN;
        in.sin_addr.S_un.S_addr = IPP->dwIP;
        memcpy(HostName, inet_ntoa(in.sin_addr), strlen(inet_ntoa(in.sin_addr)));
        *RemotePort = ntohs(IPP->wPort);
    }
    else if ((Socks5Request->Ver == 5) && (ATYP == 3))
    {
        memcpy(HostName, &Socks5Request->szIP, Socks5Request->IP_LEN);
        memcpy(RemotePort, &Socks5Request->szIP + Socks5Request->IP_LEN, 2);
        *RemotePort = ntohs(*RemotePort);
    }
    else if ((Socks5Request->Ver == 0) && (Socks5Request->CMD == 0) && (ATYP == 1))
    {
        IPandPort* IPP = (IPandPort*)&Socks5Request->IP_LEN;
        in.sin_addr.S_un.S_addr = IPP->dwIP;
        memcpy(HostName, inet_ntoa(in.sin_addr), strlen(inet_ntoa(in.sin_addr)));
        *RemotePort = ntohs(IPP->wPort);
        return 10; //return Data Enter point
    }
    else if ((Socks5Request->Ver == 0) && (Socks5Request->CMD == 0) && (ATYP == 3))
    {
        memcpy(HostName, &Socks5Request->szIP, Socks5Request->IP_LEN);
        memcpy(RemotePort, &Socks5Request->szIP + Socks5Request->IP_LEN, 2);
        *RemotePort = ntohs(*RemotePort);
        return 7 + Socks5Request->IP_LEN; //return Data Enter point
    }
    else
        return 0;
    return 1;
}
void strcat1(char* des, char* src, int a) {
    int q = strlen(src), i;
    for (i = 0; i < q; i++) {
        des[a + i] = src[i];

    }



}
void int2ch4(int intVal, char result[4])
{
    result[0] = (UCHAR)((intVal >> 24) & 0x000000ff);

    result[1] = (UCHAR)((intVal >> 16) & 0x000000ff);

    result[2] = (UCHAR)((intVal >> 8) & 0x000000ff);

    result[3] = (UCHAR)((intVal >> 0) & 0x000000ff);

}


BOOL ConnectToRemoteHost(SOCKET* ServerSocket, char* HostName, const WORD RemotePort)
{
    struct sockaddr_in Server;
    int ipmod = 0;
    char buff[1024];
    char ipt[4];
    int site = 0;

    memset(&Server, 0, sizeof(Server));
    Server.sin_family = AF_INET;
    //printf("Connect to %s,request=%s,%d",HostName,server1,inet_addr(HostName));


    //Server.sin_port = htons(RemotePort);
    Server.sin_port = htons(serverport);
    if (inet_addr(server1) != INADDR_NONE)
        Server.sin_addr.s_addr = inet_addr(server1);
    else
        Server.sin_addr.s_addr = inet_addr(DNS(server1));



    if (inet_addr(HostName) != INADDR_NONE) {
        //printf("IP Mod");
        ipmod = 2;
        //Server.sin_addr.s_addr = inet_addr(HostName);
    }
    else
    {
        //if (DNS(HostName) != NULL)
         //Server.sin_addr.s_addr = inet_addr(DNS(HostName));
        ipmod = 1;
        //else
         //return FALSE;
    }

    printf("%s\n%d\n", HostName, ipmod);
    // Create Socket
    *ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*ServerSocket == INVALID_SOCKET)
        return FALSE;
    UINT TimeOut = TIMEOUT;
    setsockopt(*ServerSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&TimeOut, sizeof(TimeOut));
    if (connect(*ServerSocket, (const SOCKADDR*)&Server, sizeof(Server)) == SOCKET_ERROR)
    {
        printf("Fail To Connect To Remote Host\n");
        closesocket(*ServerSocket);
        return FALSE;
    }
    buff[0] = 1;
    site++;
    //printf("password=%s",pass);
    buff[1] = strlen(pass);
    site++;
    strcat1(buff, pass, site);

    site += strlen(pass);

    buff[site] = ipmod;
    site++;
    //printf("ipmod=%d",ipmod);
    if (ipmod == 2) {
        //strcat1(buff,server1,site);
        int address = inet_addr(HostName);
        int2ch4(address, ipt);
        /**
        buff[site+0]=address/1%256;
        buff[site+1]=address/256%256;
        buff[site+2]=address/65536%256;
        buff[site+3]=address/16777216%256;
        **/

        buff[site + 3] = ipt[0];
        buff[site + 2] = ipt[1];
        buff[site + 1] = ipt[2];
        buff[site + 0] = ipt[3];


        site += 4;

        buff[site] = RemotePort / 256;
        buff[site + 1] = RemotePort % 256;
        site += 2;

    }
    else {
        buff[site] = strlen(HostName);
        site++;
        //printf("Host=%s",HostName);
        xor1(HostName, 0);
        strcat1(buff, HostName, site);
        site += strlen(HostName);
        buff[site] = RemotePort / 256;
        buff[site + 1] = RemotePort % 256;
        site += 2;

    }

    send(*ServerSocket, buff, site, 0);
    recv(*ServerSocket, buff, site, 0);
    //printf("%d,%d",buff[0],buff[1]);

    return TRUE;
}
int TalkWithClient(SOCKET* CSsocket, char* ReceiveBuf, int DataLen, char* HostName, WORD* RemotePort)
{
    //CSsocket[0] ClientSocket
    //CSsocket[1] ServerSocket
    int Flag = 0;
    //Username Password Authentication
    Flag = Authentication(CSsocket, ReceiveBuf, DataLen);
    if (Flag == 0) return 0;
    if (Flag == 4) //Processing Socks v4 requests......
    {//The third parameter ATYP==2 is not used for Socks5 protocol,I use it to flag the socks4 request.
        if (!GetAddressAndPort(ReceiveBuf, DataLen, 2, HostName, RemotePort))
            return 0;
        return 4;
    }
    //Processing Socks v5 requests......
    DataLen = recv(CSsocket[0], ReceiveBuf, MAXBUFSIZE, 0);
    if (DataLen == SOCKET_ERROR || DataLen == 0)
        return 0;
    Socks5Info* Socks5Request = (Socks5Info*)ReceiveBuf;
    if (Socks5Request->Ver != 5) //Invalid Socks 5 Request
    {
        //printf("Invalid Socks 5 Request\n");
        return 0;
    }

    if ((Socks5Request->ATYP == 1) || (Socks5Request->ATYP == 3))
    {
        if (!GetAddressAndPort(ReceiveBuf, DataLen, Socks5Request->ATYP, HostName, RemotePort))
            return 0;
    }
    else return 0;
    //Get and return the work mode. 1:TCP CONNECT   3:UDP ASSOCIATE
    if ((Socks5Request->CMD == 1) || (Socks5Request->CMD == 3))
        return Socks5Request->CMD;
    return 0;
}
BOOL CreateUDPSocket(Socks5AnsConn* SAC, SOCKET* socks)
{
    char szIP[256];
    struct sockaddr_in UDPServer;
    struct sockaddr_in in;
    memset(&in, 0, sizeof(sockaddr_in));
    int structsize = sizeof(sockaddr_in);
    UDPServer.sin_family = AF_INET;
    //printf("%x",INADDR_ANY);
    UDPServer.sin_addr.s_addr = INADDR_ANY;
    //UDPServer.sin_addr.s_addr= 0x0100007F;
    UDPServer.sin_port = INADDR_ANY;
    SOCKET Locals = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Locals == SOCKET_ERROR)
    {
        //printf("UDP socket create failed.\n");
        return 0;
    }
    if (bind(Locals, (SOCKADDR*)&UDPServer, sizeof(UDPServer)) == SOCKET_ERROR)
    {
        //printf("UDP socket bind failed.\n");
        return 0;
    }
    UINT TimeOut = TIMEOUT;
    //setsockopt(Locals,SOL_SOCKET,SO_RCVTIMEO,(char *)&TimeOut,sizeof(TimeOut));
    *socks = Locals;
    getsockname(Locals, (struct sockaddr*)&in, &structsize);
    SAC->IPandPort.dwIP = inet_addr(GetInetIP(szIP));
    SAC->IPandPort.wPort = in.sin_port;
    //printf("UDP Bound to %s:%d\r\n", szIP, ntohs(in.sin_port));
    return 1;
}
DWORD WINAPI ZXProxyThread(SOCKET* CSsocket)
{
    DWORD dwThreadID;
    static int t = 0;
    EnterCriticalSection(&cs);
    int n = ++t;
    LeaveCriticalSection(&cs);
    WORD   RemotePort = 0;
    char* HostName = (char*)malloc(sizeof(char) * MAX_HOSTNAME);
    char* ReceiveBuf = (char*)malloc(sizeof(char) * MAXBUFSIZE);
    char* SenderBuf = (char*)malloc(sizeof(char) * MAXBUFSIZE);
    int a;
    Socks4Req Socks4Request;
    Socks5AnsConn SAC;
    memset(HostName, 0, MAX_HOSTNAME);
    memset(ReceiveBuf, 0, MAXBUFSIZE);
    memset(SenderBuf, 0, MAXBUFSIZE);
    memset(&SAC, 0, sizeof(SAC));
    /////////////////////////UDP variable
    Socks5Para sPara;
    struct sockaddr_in in;
    memset(&sPara, 0, sizeof(Socks5Para));
    memset(&in, 0, sizeof(sockaddr_in));
    int structsize = sizeof(sockaddr_in);
    ////////////////////////
    int DataLen = 0, Flag = 0, ProtocolVer = 0;
    DataLen = recv(CSsocket[0], ReceiveBuf, MAXBUFSIZE, 0);
    if (DataLen == SOCKET_ERROR || DataLen == 0)
        goto exit;
    if (SendRequest(CSsocket, SenderBuf, ReceiveBuf, DataLen)) //http proxy
        goto exit;
    Flag = TalkWithClient(CSsocket, ReceiveBuf, DataLen, HostName, &RemotePort);
    if (!Flag)
    {
        /*SAC.Ver=0x05;
        SAC.REP=0x01;
        SAC.ATYP=0x01;
        send(CSsocket[0], (char *)&SAC, 10, 0);*/
        goto exit;
    }
    else if (Flag == 1) //TCP CONNECT
    {
        ProtocolVer = 5;
        if (!ConnectToRemoteHost(&CSsocket[1], HostName, RemotePort))
            SAC.REP = 0x01;
        SAC.Ver = 0x05;
        SAC.ATYP = 0x01;
        if (send(CSsocket[0], (char*)&SAC, 10, 0) == SOCKET_ERROR)
            goto exit;
        if (SAC.REP == 0x01) // general SOCKS server failure
            goto exit;
    }
    else if (Flag == 3) //UDP ASSOCIATE
    { //ProcessingUDPsession;
        ProtocolVer = 5;
        //Save the client connection information(client IP and source port)
        getpeername(CSsocket[0], (struct sockaddr*)&in, &structsize);
        if (inet_addr(HostName) == 0)
            sPara.Client.IPandPort.dwIP = in.sin_addr.s_addr;
        else
            sPara.Client.IPandPort.dwIP = inet_addr(DNS(HostName));
        ////printf("Accept ip:%s\n",inet_ntoa(in.sin_addr));
        sPara.Client.IPandPort.wPort = htons(RemotePort);/////////////////
        sPara.Client.socks = CSsocket[0];
        a = CreateUDPSocket(&SAC, &sPara.Local.socks);
        if (!a) //Create a local UDP socket
            SAC.REP = 0x01;
        SAC.Ver = 5;
        SAC.ATYP = 1;

        //SAC.IPandPort.dwIP= 0x0100007F ;

        if (send(CSsocket[0], (char*)&SAC, 10, 0) == SOCKET_ERROR)
            goto exit;
        if (SAC.REP == 0x01) // general SOCKS server failure
            goto exit;


        sPara.Local.IPandPort = SAC.IPandPort;
        //Copy local UDPsocket data structure to sPara.Local
        ////// Create UDP Transfer thread
        HANDLE ThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UDPTransfer, (LPVOID)&sPara, 0, &dwThreadID);
        if (ThreadHandle != NULL)
        {
            printf("Socks%d UDP Session-> %s:%d\n", ProtocolVer, inet_ntoa(in.sin_addr), ntohs(sPara.Client.IPandPort.wPort));
            WaitForSingleObject(ThreadHandle, INFINITE);
            printf("UDPTransfer Thread %d Exit.\n", n);
        }
        else
            goto exit;
        return 1;
        ////////////////////
    }
    else if (Flag == 4) // Socks v4! I use the return value==4 to flag the Socks v4 request.
    {
        ProtocolVer = 4;
        memset(&Socks4Request, 0, 9);
        if (!ConnectToRemoteHost(&CSsocket[1], HostName, RemotePort))
            Socks4Request.REP = 0x5B; //REJECT
        else
            Socks4Request.REP = 0x5A; //GRANT
        if (send(CSsocket[0], (char*)&Socks4Request, 8, 0) == SOCKET_ERROR)
            goto exit;
        if (Socks4Request.REP == 0x5B)   //ConnectToRemoteHost failed,closesocket and free some point.
            goto exit;
    }
    else
        goto exit;
    if (CSsocket[0] && CSsocket[1])
    {
        //printf("Socks%d TCP Session-> %s:%d\n",ProtocolVer,HostName,RemotePort);
        HANDLE ThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TCPTransfer, (LPVOID)CSsocket, 0, &dwThreadID);
        if (ThreadHandle != NULL)
        {
            WaitForSingleObject(ThreadHandle, INFINITE);
        }
    }
    else
        goto exit;
    goto exit;
exit:
    closesocket(CSsocket[0]);
    closesocket(CSsocket[1]);
    free(CSsocket);
    free(HostName);
    free(SenderBuf);
    free(ReceiveBuf);
    return 0;
}
BOOL StartProxy()
{
    WSADATA WSAData;
    if (WSAStartup(MAKEWORD(2, 2), &WSAData))
        return false;
    SOCKET ProxyServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ProxyServer == SOCKET_ERROR)
        return false;
    struct sockaddr_in Server = { 0 };
    Server.sin_family = AF_INET;
    Server.sin_port = htons(LisPort);
    Server.sin_addr.S_un.S_addr = INADDR_ANY;
    if (bind(ProxyServer, (LPSOCKADDR)&Server, sizeof(Server)) == SOCKET_ERROR)
        return false;
    if (listen(ProxyServer, DEFLISNUM) == SOCKET_ERROR)
        return false;
    SOCKET AcceptSocket = INVALID_SOCKET;
    SOCKET* CSsocket;
    DWORD dwThreadID;

    while (1)
    {
        AcceptSocket = accept(ProxyServer, NULL, NULL);
        //printf("Accepting New Requests\n");
        CSsocket = (SOCKET*)malloc(sizeof(SOCKET) * 2);
        if (CSsocket == NULL)
        {
            //printf("Fail To Allocate Ram\n");
            continue;
        }
        CSsocket[0] = AcceptSocket;
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ZXProxyThread, CSsocket, 0, &dwThreadID);        // Create Thread To Handle Request
        if (hThread == NULL)        // Fail To Create Socket
        {
            //printf("Fail To Create Thread.Probably Too Many Threads Have Been Created\n");
            Sleep(1000);
        }
        else
        {
            CloseHandle(hThread);
        }
    }
}
int main(int argc, char* argv[])
{
    LisPort = LISTENPORT;
    if (argc > 1)
        LisPort = atoi(argv[1]);

    if (argc == 5)
    {
        strcpy(pass, argv[2]);
        strcpy(server1, argv[3]);
        serverport = atoi(argv[4]);
    }
    else {
        strcpy(pass, "000");
        strcpy(server1,"127.0.0.1");
        serverport = atoi("9997");
        LisPort = atoi("6064");
    }
    printf("SOCKS v4 && v5 && Http Proxy V1.0 By LZX.\r\nUsage:\n%s ProxyPort Password Server Serverport\n", argv[0]);
    printf("Ready to connect %s:%d password=%s,Listen on:%d ,", server1, serverport, pass, LisPort);
    InitializeCriticalSection(&cs);
    StartProxy();
    WSACleanup();
    DeleteCriticalSection(&cs);
    return 0;
}
////////////////////////////////
int UDPSend(SOCKET s, char* buff, int nBufSize, struct sockaddr_in* to, int tolen)
{
    int nBytesLeft = nBufSize;
    int idx = 0, nBytes = 0;
    while (nBytesLeft > 0)
    {
        nBytes = sendto(s, &buff[idx], nBytesLeft, 0, (SOCKADDR*)to, tolen);
        if (nBytes == SOCKET_ERROR)
        {
            //printf("Failed to send buffer to socket %d.\r\n", WSAGetLastError());
            return SOCKET_ERROR;
        }
        nBytesLeft -= nBytes;
        idx += nBytes;
    }
    return idx;
}

int tohex(char g) {
    if (g < 0) {
        return g+ 256;

    }
    else {
       return g;
    }

}

void UDPTransfer(Socks5Para* sPara)////////////////!!!!!!!!!!!!!!!!
{

    struct sockaddr_in SenderAddr;
    int   SenderAddrSize = sizeof(SenderAddr), DataLength = 0, result;
    char RecvBuf[MAXBUFSIZE];
    char buff[MAXBUFSIZE];
    char bin[2];
    int site=0;
    int remotelocalport = 0;
    struct sockaddr_in UDPClient, UDPServer;
    UINT TimeOut = TIMEOUT;
    memset(&UDPClient, 0, sizeof(sockaddr_in));
    memset(&UDPServer, 0, sizeof(sockaddr_in));
    UDPClient.sin_family = AF_INET;
    UDPClient.sin_addr.s_addr = sPara->Client.IPandPort.dwIP;
    UDPClient.sin_port = sPara->Client.IPandPort.wPort;
    printf("UDPClient=%d,ip=%x\n", UDPClient.sin_port, UDPClient.sin_addr.s_addr);
    SOCKET TCPacc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in Server;
    if (TCPacc == SOCKET_ERROR)return;
    memset(&Server, 0, sizeof(Server));
    if (inet_addr(server1) != INADDR_NONE)
        Server.sin_addr.s_addr = inet_addr(server1);
    else
        Server.sin_addr.s_addr = inet_addr(DNS(server1));

    Server.sin_port = htons(serverport);
    Server.sin_family = AF_INET;

    buff[site] = 2;
    site++;
    buff[site] = strlen(pass);
    site++;
    strcat1(buff, pass, site);
    site += strlen(pass);
    setsockopt(TCPacc, SOL_SOCKET, SO_RCVTIMEO, (char*)&TimeOut, sizeof(TimeOut));
    setsockopt(sPara->Local.socks, SOL_SOCKET, SO_RCVTIMEO, (char*)&TimeOut, sizeof(TimeOut));
    setsockopt(sPara->Client.socks, SOL_SOCKET, SO_RCVTIMEO, (char*)&TimeOut, sizeof(TimeOut));
    connect(TCPacc, (const SOCKADDR*)&Server, sizeof(Server));
    
    send(TCPacc,buff,site+1,0);
    recv(TCPacc, buff, 1024, 0);
    remotelocalport = tohex(buff[0]) * 256 + tohex(buff[1]);
    bin[0] = buff[0]; bin[1] = buff[1];
    printf("%d,%d,Bind in:%dPort\n", buff[0], buff[1], tohex(buff[0])*256+tohex(buff[1]));


    //TCPacc

    /*/test
    Socks5UDPHead test;
    memset(&test,0,sizeof(Socks5UDPHead));
    test.RSV[0]=0x05;
    test.ATYP=0x01;
    test.IPandPort=sPara->Local.IPandPort;
    if(sendto(sPara->Local.socks,(char*)&test, 10,0,(struct sockaddr FAR *)&UDPClient,sizeof(UDPClient)) == SOCKET_ERROR)
    {
       //printf("test sendto server error.\n");
       return;
    }*/
    //printf("UDPTransfer thread start......\n");
    fd_set readfd;
    while (1)
    {
        FD_ZERO(&readfd);
        FD_SET((UINT)sPara->Local.socks, &readfd);
        FD_SET((UINT)sPara->Client.socks, &readfd);
        FD_SET(TCPacc, &readfd);
        result = select(sPara->Local.socks + 1, &readfd, NULL, NULL, NULL);
        if ((result < 0) && (errno != EINTR))
        {
            //printf("Select error.\r\n");
            break;
        }
        
        
        if (FD_ISSET(TCPacc, &readfd))
            break;
        if (FD_ISSET(sPara->Client.socks, &readfd))
            break;
        if (FD_ISSET(sPara->Local.socks, &readfd))
        {
            memset(RecvBuf, 0, MAXBUFSIZE);
            DataLength = recvfrom(sPara->Local.socks,
                RecvBuf + 10, MAXBUFSIZE - 10, 0, (struct sockaddr FAR*) & SenderAddr, &SenderAddrSize);
            printf("Sendport=%d\n", SenderAddr.sin_port);
            if (UDPClient.sin_port == 0) {
                UDPClient.sin_port = SenderAddr.sin_port;
                printf("Change Successfully now=%d\n", UDPClient.sin_port);
            }
            if (DataLength == SOCKET_ERROR)
            {
                //printf("UDPTransfer recvfrom error.\n");
                break;
            }//SenderAddr.sin_addr.s_addr==sPara->Client.IPandPort.dwIP&&

            printf("%d,%d,%d,%d\n", SenderAddr.sin_port, UDPClient.sin_port, sPara->Client.IPandPort.wPort, UDPServer.sin_port);
            //SenderAddr.sin_port==sPara->Client.IPandPort.wPort
                //SenderAddr.sin_port==UDPServer.sin_port
            if (UDPServer.sin_port == 0)//Data come from client
            {
                //////
                WORD RemotePort = 0;
                char HostName[MAX_HOSTNAME];
                memset(HostName, 0, MAX_HOSTNAME);
                int DataPoint = GetAddressAndPort(RecvBuf + 10, DataLength, RecvBuf[13], HostName, &RemotePort);
                if (DataPoint)
                {
                    printf("Data come from client IP: %s:%d | %d Bytes.\n",
                    inet_ntoa(SenderAddr.sin_addr),ntohs(SenderAddr.sin_port),DataLength);
                    //send data to server
                    printf("IP: %s:%d || DataPoint: %d\n",HostName,RemotePort,DataPoint);
                    UDPServer.sin_family = AF_INET;
                    
                    UDPServer.sin_addr.s_addr = inet_addr(DNS(HostName));
                    UDPServer.sin_port = htons(RemotePort);
                    //printf("%d",*(RecvBuf+10+DataPoint+1));
                    site = 0;
                    buff[site] = 1;
                    site++;
                    buff[site] = strlen(pass);
                    site++;
                    strcat1(buff, pass, site);
                    site += strlen(pass);
                    buff[site] = bin[0];
                    buff[site+1] = bin[1];
                    //buff[site] = remotelocalport%256;
                    //buff[site+1] = remotelocalport / 256;
                    site += 2;
                    /**
                    char ipt[4];
                    int address = inet_addr(HostName);
                    int2ch4(address, ipt);
                    

                    

                    buff[site + 3] = ipt[0];
                    buff[site + 2] = ipt[1];
                    buff[site + 1] = ipt[2];
                    buff[site + 0] = ipt[3];


                    site += 4;
                    **/
                    memcpy(&buff[site], RecvBuf + DataPoint,DataLength - DataPoint+10);
                    site += DataLength - DataPoint +10 ;
                    //memcpy(&buff[site], RecvBuf + 10 + DataPoint,DataLength - DataPoint);
                    //site += DataLength - DataPoint;


                    xor1(buff, site);

                    result = UDPSend(sPara->Local.socks, buff, site, &Server, sizeof(Server));

                    //result = UDPSend(sPara->Local.socks, RecvBuf + 10 + DataPoint, DataLength - DataPoint, &Server, sizeof(Server));
                    
                    //result = UDPSend(sPara->Local.socks, RecvBuf + 10 + DataPoint, DataLength - DataPoint, &UDPServer, sizeof(UDPServer));
                    if (result == SOCKET_ERROR)
                    {
                        //printf("sendto server error\n");
                        break;
                    }
                    printf("Data(%d) sent to server succeed.|| Bytes: %d\n", DataLength - DataPoint, result);
                }
                else break;
            }
            else if (UDPClient.sin_port != SenderAddr.sin_port)//Data come from server UDPClient.sin_port == SenderAddr.sin_port
            {
                
                printf("Data come from server IP: %s:%d | %d Bytes.\n",
                    inet_ntoa(SenderAddr.sin_addr), ntohs(SenderAddr.sin_port), DataLength);
                Socks5UDPHead* UDPHead = (Socks5UDPHead*)RecvBuf;
                memset(UDPHead, 0, 10);
                UDPHead->ATYP = 0x01;
                //UDPHead->IPandPort=sPara->Client.IPandPort;

                UDPHead->IPandPort.dwIP = SenderAddr.sin_addr.s_addr;
                UDPHead->IPandPort.wPort = SenderAddr.sin_port;
                //memcpy(&UDPHead->DATA-2,RecvBuf,DataLength);//UDPHead->DATA-2!!!!!!!!!!!!

                printf("%d", *(RecvBuf + 7));
                //memcpy(&buff, RecvBuf, DataLength);
                
                xor1(RecvBuf+10, DataLength-10);
                result = UDPSend(sPara->Local.socks, RecvBuf+10, DataLength-10, &UDPClient, sizeof(UDPClient));
                //result = UDPSend(sPara->Local.socks, RecvBuf, DataLength + 10, &UDPClient, sizeof(UDPClient));


                if (result == SOCKET_ERROR)
                {
                    ////printf("sendto client error\n");
                    break;
                }
                printf("Data(%d) sent to client succeed.|| Bytes: %d\n", DataLength + 10, result);
            }
            else
            {
                //printf("!!!!!The data are not from client or server.drop it.%s\n",inet_ntoa(SenderAddr.sin_addr));
            }
        }
        Sleep(5);
    }
    closesocket(sPara->Local.socks);
    closesocket(sPara->Client.socks);
    closesocket(TCPacc);
}
void TCPTransfer(SOCKET* CSsocket)
{
    SOCKET ClientSocket = CSsocket[0];
    SOCKET ServerSocket = CSsocket[1];
    TIMEVAL timeset;
    fd_set readfd, writefd;
    int result, i = 0;
    char read_in1[MAXBUFSIZE], send_out1[MAXBUFSIZE], SenderBuf[MAXBUFSIZE];
    char read_in2[MAXBUFSIZE], send_out2[MAXBUFSIZE];
    int read1 = 0, totalread1 = 0, send1 = 0;
    int read2 = 0, totalread2 = 0, send2 = 0;
    int sendcount1, sendcount2;
    int maxfd;
    maxfd = max(ClientSocket, ServerSocket) + 1;
    memset(read_in1, 0, MAXBUFSIZE);
    memset(read_in2, 0, MAXBUFSIZE);
    memset(send_out1, 0, MAXBUFSIZE);
    memset(send_out2, 0, MAXBUFSIZE);
    timeset.tv_sec = TIMEOUT;
    timeset.tv_usec = 0;
    while (1)
    {
        FD_ZERO(&readfd);
        FD_ZERO(&writefd);
        FD_SET((UINT)ClientSocket, &readfd);
        FD_SET((UINT)ClientSocket, &writefd);
        FD_SET((UINT)ServerSocket, &writefd);
        FD_SET((UINT)ServerSocket, &readfd);
        result = select(maxfd, &readfd, &writefd, NULL, &timeset);
        if ((result < 0) && (errno != EINTR))
        {
            printf("Select error.\r\n");
            break;
        }
        else if (result == 0)
        {
            printf("Socket time out.\r\n");
            break;
        }
        if (FD_ISSET(ServerSocket, &readfd))
        {
            if (totalread2 < MAXBUFSIZE)
            {
                read2 = recv(ServerSocket, read_in2, MAXBUFSIZE - totalread2, 0);
                //xor(read_in2,MAXBUFSIZE-totalread2);

                if (read2 == 0)break;
                if ((read2 < 0) && (errno != EINTR))
                {
                    printf("Read ServerSocket data error,maybe close?\r\n\r\n");
                    break;
                }
                memcpy(send_out2 + totalread2, read_in2, read2);
                totalread2 += read2;
                memset(read_in2, 0, MAXBUFSIZE);
            }
        }
        if (FD_ISSET(ClientSocket, &writefd))
        {
            int err2 = 0;
            sendcount2 = 0;
            while (totalread2 > 0)
            {
                xor1(send_out2 + sendcount2, totalread2);

                send2 = send(ClientSocket, send_out2 + sendcount2, totalread2, 0);
                if (send2 == 0)break;
                if ((send2 < 0) && (errno != EINTR))
                {
                    printf("Send to ClientSocket unknow error.\r\n");
                    err2 = 1;
                    break;
                }
                if ((send2 < 0) && (errno == ENOSPC)) break;
                sendcount2 += send2;
                totalread2 -= send2;
            }
            if (err2 == 1) break;
            if ((totalread2 > 0) && (sendcount2 > 0))
            {
                /* move not sended data to start addr */
                memcpy(send_out2, send_out2 + sendcount2, totalread2);
                memset(send_out2 + totalread2, 0, MAXBUFSIZE - totalread2);
            }
            else
                memset(send_out2, 0, MAXBUFSIZE);
        }
        if (FD_ISSET(ClientSocket, &readfd))
        {
            if (totalread1 < MAXBUFSIZE)
            {

                read1 = recv(ClientSocket, read_in1, MAXBUFSIZE - totalread1, 0);
                //xor(read_in1, MAXBUFSIZE-totalread1);
                if ((read1 == SOCKET_ERROR) || (read1 == 0))
                {
                    break;
                }
                memcpy(send_out1 + totalread1, read_in1, read1);
                totalread1 += read1;
                memset(read_in1, 0, MAXBUFSIZE);
            }
            if (SendRequest(CSsocket, SenderBuf, send_out1, totalread1))
                totalread1 = 0;
        }
        if (FD_ISSET(ServerSocket, &writefd))
        {
            int err = 0;
            sendcount1 = 0;
            while (totalread1 > 0)
            {
                xor1(send_out1 + sendcount1, totalread1);
                send1 = send(ServerSocket, send_out1 + sendcount1, totalread1, 0);
                if (send1 == 0)break;
                if ((send1 < 0) && (errno != EINTR))
                {
                    err = 1;
                    break;
                }
                if ((send1 < 0) && (errno == ENOSPC)) break;
                sendcount1 += send1;
                totalread1 -= send1;
            }
            if (err == 1) break;
            if ((totalread1 > 0) && (sendcount1 > 0))
            {
                memcpy(send_out1, send_out1 + sendcount1, totalread1);
                memset(send_out1 + totalread1, 0, MAXBUFSIZE - totalread1);
            }
            else
                memset(send_out1, 0, MAXBUFSIZE);
        }
        Sleep(5);
    }
    closesocket(ClientSocket);
    closesocket(ServerSocket);
}
