#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib") // Link against the Winsock library

// build with x86_64-w64-mingw32-gcc socket.c -o socket_program.exe -lws2_32

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    char recvBuffer[1024];
    int recvSize;
    int connectionResult;

    // Initialize Winsock
    WSAStartup(MAKEWORD(2,2), &wsaData);

    while(1) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            printf("Could not create socket : %d" , WSAGetLastError());
            return 1;
        }

        server.sin_addr.s_addr = inet_addr("127.0.0.1");
        server.sin_family = AF_INET;
        server.sin_port = htons(81);  // Ensure this matches your ncat listening port

        
        connectionResult = connect(sock , (struct sockaddr *)&server , sizeof(server));
        if (connectionResult < 0) {
            printf("Connect failed with error code : %d" , WSAGetLastError());
            closesocket(sock);
            Sleep(3000); 
            continue; 
        }

        printf("Connected\n");

        
        recvSize = recv(sock , recvBuffer , sizeof(recvBuffer) , 0);
        if(recvSize == SOCKET_ERROR) {
            printf("Recv failed with error code : %d" , WSAGetLastError());
        } else {
            recvBuffer[recvSize] = '\0'; 
            printf("Reply received: %s\n", recvBuffer);
        }

        closesocket(sock);
        Sleep(3000); 
    }

    WSACleanup();
    return 0;
}
