#include "comnet.c"

int main(int argc, char const *argv[])
{
    int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(packet_socket == -1) {
        perror("Error al abrir el socket.");
        exit(1);
    } else {
        perror("Exito al abrir el socket.");
        int index = getData(packet_socket);
        printf("El indice es %d\n", index);

		char ip_string[14];

		printf("Introduce la direccion IP a buscar\n -> ");
		scanf("%s", ip_string);

		stringToIP(ip_string);
		memcpy(dest_IP, IP, 4);
		
		ARPframe(frame_s, my_MAC, my_IP, dest_MAC, dest_IP);
		//printFrame(frame_s, 42);
		sendFrame(packet_socket, index, frame_s, 42);
		receiveFrame(packet_socket, frame_r);
    }

    close(packet_socket);

    return 0;
}