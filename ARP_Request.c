#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <sys/time.h>


unsigned char MACOrigen[6];
unsigned char IPOrigen[4];

unsigned char MACDestino[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
unsigned char IPDestino[4] = {0x00,0x00,0x00,0x00};

unsigned char tramaEnv[1514], tramaRec[1514];
unsigned char MACbro[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char ethertype[2] = {0x08,0x06};
unsigned char HW[2] = {0x00,0x01};
unsigned char PR[2] = {0x08,0x00};
unsigned char LDH[1] = {0x06};
unsigned char LDP[1] = {0x04};
unsigned char epcode_s[2] = {0x00, 0x01};
unsigned char epcode_r[2] = {0x00, 0x02};

struct timeval start, end;
long mtime, seconds, useconds;

int obtenerDatos(int ds)
{
	struct ifreq nic;
	int indice,i;
	char nombre[10], dir_ip[14];
	
	//printf("Insertar el nombre de la interfaz:  ");
	//scanf("%s", nombre);

	printf("Usando la interfaz wlp3s0\n\n");
	strcpy(nombre, "wlp3s0");
	//strcpy(nombre, "enp2s0");
	strcpy(nic.ifr_name, nombre);
	
	if(ioctl(ds, SIOCGIFINDEX, &nic) == -1)
	{
		perror("Error al obtener el indice\n");
		exit(1);
	}
	else
	{
		indice = nic.ifr_ifindex;
	}
	
	if(ioctl(ds, SIOCGIFHWADDR, &nic ) == -1)
	{
		perror("Error al obtener la MAC\n");
		exit(1);
	}
    else
    {
		memcpy(MACOrigen, nic.ifr_hwaddr.sa_data+0, 6);
		printf("Mi direccion MAC es: ");
		
		for( i = 0 ; i < 6 ; i++ )
			printf("%.2X:", MACOrigen[i]);
	}

	if(ioctl(ds, SIOCGIFADDR, &nic) == -1)
	{
		perror("Error al obtener la dirección IP\n");
		exit(1);
	}
	else
	{
		memcpy(IPOrigen, nic.ifr_addr.sa_data+2, 4);
		printf("\nMi direccion IP es: ");
		
		for( i = 0 ; i < 4 ; i++ ){
				if( i == 3 ){
					printf("%d", IPOrigen[i]);
				}
				else {
					printf("%d.", IPOrigen[i]);
				}
		}

	}

	printf("\n");

	return indice;
}

void estructuraTrama(unsigned char *trama)
{
	memcpy(trama+0, MACbro, 6);
	memcpy(trama+6, MACOrigen, 6);
	memcpy(trama+12, ethertype, 2);
	memcpy(trama+14, HW, 2);
	memcpy(trama+16, PR, 2);
	memcpy(trama+18, LDH, 1);
	memcpy(trama+19, LDP, 1);
	memcpy(trama+20, epcode_s, 2);
	memcpy(trama+22, MACOrigen, 6);
	memcpy(trama+28, IPOrigen, 4);
	memcpy(trama+32, MACDestino, 6);

	IPDestino[0] = IPOrigen[0];
	IPDestino[1] = IPOrigen[1];
	IPDestino[2] = IPOrigen[2];
	IPDestino[3] = 0x53;

	memcpy(trama+38, IPDestino, 4);
}

void enviaTrama(int ds, int indice, unsigned char *trama)
{
	int tam;   
	struct sockaddr_ll interfaz;
	memset(&interfaz, 0x00, sizeof(interfaz));
	interfaz.sll_family = AF_PACKET;
	interfaz.sll_protocol = htons(ETH_P_ALL);
	interfaz.sll_ifindex = indice;
	tam=sendto(ds, trama, 42, 0, (struct sockaddr *)&interfaz, sizeof(interfaz));
	
	if(tam == -1)
	{
		perror("Error al enviar");
		exit(1);   
	}
	else
	{
		//perror("Exito al enviar");  
	}
}

void imprimeTrama(unsigned char *trama, int tam)
{
	int i;

	for( i = 0 ; i < tam ; i++ )
	{
		if( i%16 == 0 )
			printf("\n");
		printf("%.2x ", trama[i]);
	}

	printf("\n");
}

void recibeTrama(int ds, unsigned char *trama)
{
	int tam, flag = 0;

	gettimeofday(&start, NULL);
	mtime = 0;
    
    while(mtime < 1000){
		
		tam = recvfrom(ds, trama, 1514, MSG_DONTWAIT, NULL, 0);

		if( tam == -1 )
		{
			//perror("Error al recibir");
		}
		else
		{
			if( !memcmp(trama+0, MACOrigen, 6) && !memcmp(trama+12, ethertype, 2) && !memcmp(trama+20, epcode_r, 2) && !memcmp(trama+28, IPDestino, 4) )
			{
				imprimeTrama(trama, tam);
				flag = 1;
			}
	
		}
	
		gettimeofday(&end, NULL);

		seconds  = end.tv_sec  - start.tv_sec;
		useconds = end.tv_usec - start.tv_usec;

		mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
		
		if( flag == 1 )
		{
			printf("Elapsed time: %ld milliseconds\n", mtime);
			break;
		}

	}

	if( flag == 0 ){
		perror("Error al recibir");
		printf("Elapsed time: %ld milliseconds\n", mtime);
	}

}

int main(void)
{
	int packet_socket, indice;
    
	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(packet_socket == -1)
	{
		perror("Error al abrir el socket");
		exit(1);
	}
	else
	{
		perror("Exito al abrir el socket");
		indice = obtenerDatos(packet_socket);
        
		estructuraTrama(tramaEnv);
        enviaTrama(packet_socket, indice, tramaEnv);
		//imprimeTrama(tramaEnv, 42);
		printf("\n");
		recibeTrama(packet_socket, tramaRec);
		
	}
	
	close(packet_socket);
	return 1;
}