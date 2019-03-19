#include "comnet.h"

int getData(int sd)
{
	struct ifreq nic;
	int index, i;
	char select, interface_name[10];

	printf("Elije la interfaz de red a utilizar\n 1.-enp2s0\n 2.-wlp3s0\n 3.-Salir\n -> ");
	scanf("%c", &select);

	switch (select)
	{
		case '1':
			strcpy(interface_name, "enp2s0");
			break;
		
		case '2':
			strcpy(interface_name, "wlp3s0");
			break;
	
		default:
		printf("Error al seleccionar la interfaz de red.\n");
			exit(1);
			break;
	}

	strcpy(nic.ifr_name, interface_name);

	/* obtener el indice de la interfaz de red */
	
	if(ioctl(sd, SIOCGIFINDEX, &nic) == -1)
	{
		perror("Error al obtener el indice\n");
		exit(1);
	}
	else
	{
		index = nic.ifr_ifindex;
	}

	/* obtener mi direccion MAC */

	if(ioctl(sd, SIOCGIFHWADDR, &nic ) == -1)
	{
		perror("Error al obtener la MAC\n");
		exit(1);
	}
    else
    {
		memcpy(my_MAC, nic.ifr_hwaddr.sa_data+0, 6);
		printf("Mi direccion MAC es: ");
		
		for( i = 0 ; i < 6 ; i++ )
		{
			if(i == 5)
				printf("%.2X\n", my_MAC[i]);
			else
				printf("%.2X:", my_MAC[i]);
		}
	}

	/* obtener mi direccion IP */

	if(ioctl(sd, SIOCGIFADDR, &nic) == -1)
	{
		perror("Error al obtener la dirección IP\n");
		exit(1);
	}
	else
	{
		memcpy(my_IP, nic.ifr_addr.sa_data+2, 4);
		printf("Mi direccion IP es: ");
		
		for( i = 0 ; i < 4 ; i++ ){
			if( i == 3 )
				printf("%d\n", my_IP[i]);
			else 
				printf("%d.", my_IP[i]);
		}
	}

	/* obtener mi mascara de subred */

	if(ioctl(sd, SIOCGIFNETMASK, &nic) == -1)
	{
		perror("Error al obtener la mascara de subred\n");
		exit(1);
	}
	else
	{
		memcpy(NETMASK, nic.ifr_netmask.sa_data+2, 4);
		printf("Mi mascara de subred es: ");
		
		for( i = 0 ; i < 4 ; i++ ){
			if( i == 3 )
				printf("%d\n", NETMASK[i]);
			else 
				printf("%d.", NETMASK[i]);
		}
	}

	/* obtener la metrica */

	if(ioctl(sd, SIOCGIFMETRIC, &nic) == -1)
	{
		perror("Error al obtener la metrica\n");
		exit(1);
	}
	else
	{
		Metric = nic.ifr_metric;
		printf("Mi metrica es: %d\n", Metric);
	}

	/* obtener el MTU */

	if(ioctl(sd, SIOCGIFMTU, &nic) == -1)
	{
		perror("Error al obtener el MTU\n");
		exit(1);
	}
	else
	{
		MTU = nic.ifr_mtu;
		printf("Mi MTU es: %d\n", MTU);
	}

	printf("\n");


	return index;
}

void ARPframe(unsigned char *trama, unsigned char *s_MAC, unsigned char *s_IP, unsigned char *d_MAC, unsigned char *d_IP)
{
	memcpy(trama+0, bro_MAC, 6);
	memcpy(trama+6, my_MAC, 6);
	memcpy(trama+12, ethertype_ARP, 2);
	memcpy(trama+14, HW, 2);
	memcpy(trama+16, PR, 2);
	memcpy(trama+18, LDH, 1);
	memcpy(trama+19, LDP, 1);
	memcpy(trama+20, epcode_ARP_request, 2);
	memcpy(trama+22, s_MAC, 6);
	memcpy(trama+28, s_IP, 4);
	memcpy(trama+32, d_MAC, 6);
	memcpy(trama+38, d_IP, 4);
}

void frame(unsigned char *trama)
{
	memcpy(trama+0, alameda_MAC_WLAN, 6);
	memcpy(trama+6, my_MAC, 6);
	memcpy(trama+12, ethertype_ethernet, 2);
	memcpy(trama+14, "Quintanilla Network", 40);
}

void sendFrame(int sd, int index, unsigned char *frame, int frame_size)
{
	int size;   
	struct sockaddr_ll interface;
	
	memset(&interface, 0x00, sizeof(interface));
	printf("\n");
	interface.sll_family = AF_PACKET;
	interface.sll_protocol = htons(ETH_P_ALL);
	interface.sll_ifindex = index;
	
	size = sendto(sd, frame, frame_size, 0, (struct sockaddr *)&interface, sizeof(interface));
	
	if(size == -1)
	{
		perror("Error al enviar");
		exit(1);   
	}
	else
	{
		//printf("Exito al enviar\n");  
	}
}

void printFrame(unsigned char *frame, int size)
{
	int i;

	for( i = 0 ; i < size ; i++ )
	{
		if( i%16 == 0 )
			printf("\n");
		printf("%.2x ", frame[i]);
	}

	printf("\n");
}

void printARPinfo(unsigned char *frame, int size)
{
	int i;
	
	if(!memcmp(frame+20, epcode_ARP_request, 2))
		printf("Solicitud ARP\n");
	else if(!memcmp(frame+20, epcode_ARP_replay, 2))
		printf("Respuesta ARP\n\n");
	
	printf("+---------------------------------------+\n");

	printf("Direccion MAC Origen: ");

	for( i = 22 ; i < 28 ; i++ )
	{
		if(i == 27)
			printf("%.2X\n", frame[i]);
		else
			printf("%.2X:", frame[i]);
	}

	printf("Direccion IP Origen: ");

	for( i = 28 ; i < 32 ; i++ )
	{
		if( i == 31 )
			printf("%d\n", frame[i]);
		else 
			printf("%d.", frame[i]);
	}

	printf("Direccion MAC Destino: ");

	for( i = 32 ; i < 38 ; i++ )
	{
		if(i == 37)
			printf("%.2X\n", frame[i]);
		else
			printf("%.2X:", frame[i]);
	}

	printf("Direccion IP Destino: ");

	for( i = 38 ; i < 42 ; i++ )
	{
		if( i == 41 )
			printf("%d\n", frame[i]);
		else 
			printf("%d.", frame[i]);
	}

	printf("+---------------------------------------+\n");
}

void receiveFrame(int sd, unsigned char *frame)
{
	int size, flag = 0;

	gettimeofday(&start, NULL);
	mtime = 0;
    
    while(mtime < 1000){
		
		size = recvfrom(sd, frame, 1514, MSG_DONTWAIT, NULL, 0);

		if( size == -1 )
		{
			//perror("Error al recibir");
		}
		else
		{
			if( !memcmp(frame+0, my_MAC, 6) && !memcmp(frame+12, ethertype_ARP, 2) && !memcmp(frame+20, epcode_ARP_replay, 2) && !memcmp(frame+28, dest_IP, 4) )
			{
				//printFrame(frame, size);
				printARPinfo(frame, size);
				flag = 1;
			}
	
		}
	
		gettimeofday(&end, NULL);

		seconds  = end.tv_sec  - start.tv_sec;
		useconds = end.tv_usec - start.tv_usec;

		mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
		
		if( flag == 1 )
		{
			//printf("\nElapsed time: %ld milliseconds\n", mtime);
			break;
		}

	}

	if( flag == 0 ){
		perror("Error al recibir");
		//printf("Elapsed time: %ld milliseconds\n", mtime);
	}

}

void stringToIP(char *ip_s)
{
	inet_aton(ip_s, (struct in_addr *)IP);
}
