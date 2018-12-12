/***************************************************************************
 practica3.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones

 Compila: make
 Autor: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez
 2018 EPS-UAM v1
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <unistd.h>
#include "interface.h"
#include "practica3.h"

/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper;//y salida a pcap
uint64_t cont=0;	//Contador numero de mensajes enviados
char interface[10];	//Interface donde transmitir por ejemplo "eth0"
uint16_t ID=1;		//Identificador IP
char flag_dontfrag = 0, flag_mostrar = 0;

void handleSignal(int nsignal){
	printf("Control C pulsado (%"PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){
	
	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];

	int long_index=0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0;
	
	FILE *f = NULL;
	uint64_t file_size = 0;
	char *aux_data = NULL;

	static struct option options[] = {
		{"if",required_argument,0,'1'},
		{"ip",required_argument,0,'2'},
		{"pd",required_argument,0,'3'},
		{"f",required_argument,0,'4'},
		{"d",no_argument,0,'5'},
		{"m",no_argument,0,'6'},
		{"h",no_argument,0,'7'},
		{0,0,0,0}
	};

		//Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5:6:7", options, &long_index )) != -1) {
		switch (opt) {

			case '1' :

				flag_iface = 1;
				//Por comodidad definimos interface como una variable global
				sprintf(interface,"%s",optarg);
				printf("%s", interface);
				break;

			case '2' :

				flag_ip = 1;
				//Leemos la IP a donde transmitir y la almacenamos en orden de red
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3])) != IP_ALEN){
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}

				break;

			case '3' :

				flag_port = 1;
				//Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
				puerto_destino=atoi(optarg);
				break;

			case '4' :

				if(strcmp(optarg,"stdin")==0) {
					if (fgets(data, sizeof data, stdin)==NULL) {
						  	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				} else {
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");
					f = fopen(optarg, "r");
					if(f == NULL){
						printf("Error, el fichero no existe");
						return ERROR;
					}
					
					//Comprobamos que no esta vacio.
					if(fgets(data, sizeof data, f) == NULL){
						printf("Error leyendo desde fichero: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						fclose(f);
						return ERROR;
					}
					
					//Comprobamos que el tamaño del fichero no exceda el maximo permitido y leemos.
					fseek(f, 0, SEEK_END);
					file_size = ftell(f);
					if(file_size >= IP_DATAGRAM_MAX){
						printf("El fichero supera el tamaño maximo permitido para el datagrama"),
						fclose(f);
						return ERROR;
					}
					
					fseek(f, 0, SEEK_SET);
					aux_data = (char*)malloc(sizeof(char)*(file_size+1));
					fread(aux_data, file_size, 1, f);
					aux_data[file_size] = 0;
					fclose(f);
					strcpy(data, aux_data);
					free(aux_data);
				}
				flag_file = 1;
				break;

			case '5' :
				flag_dontfrag =1; // El usuario solicita que los paquetes se envien con el bit DF=1.
				break;

			case '6' :
				flag_mostrar =1; // El usuario solicita que se muestren en hexadecimal las tramas enviadas.
				break;

			case '7' : printf("Ayuda. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' :
			default: printf("Error. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }

	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)){
		printf("Error. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc);
		exit(ERROR);
	} else {
		printf("Interface:\n\t%s\n",interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n",IP_destino_red[0],IP_destino_red[1],IP_destino_red[2],IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n",puerto_destino);
		if (flag_dontfrag) printf("Se solicita enviar paquete con bit DF=1\n");
		if (flag_mostrar) printf("Se solicita mostrar las tramas enviadas en hexadecimal\n");
	}

	if (flag_file == 0) {
		sprintf(data,"%s","Payload "); //Deben ser pares!
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
	//Inicializamos las tablas de protocolos
	if(inicializarPilaEnviar()==ERROR){
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	//Leemos el tamano maximo de transmision del nivel de enlace
	if(obtenerMTUInterface(interface, &MTU)==ERROR)
		return ERROR;
	//Descriptor de la interface de red donde inyectar trafico
	if ((descr = pcap_open_live(interface,MTU+ETH_HLEN,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	datalink=(uint16_t)pcap_datalink(descr); //DLT_EN10MB==Ethernet

	//Descriptor del fichero de salida pcap para debugging
	descr2=pcap_open_dead(datalink,MTU+ETH_HLEN);
	pdumper=pcap_dump_open(descr2,fichero_pcap_destino);

	//Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
	//Primero, un paquete ICMP; en concreto, un ping
	pila_protocolos[0]=ICMP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=0;
	Parametros parametros_icmp; parametros_icmp.tipo=PING_TIPO; parametros_icmp.codigo=PING_CODE; parametros_icmp.bit_DF=flag_dontfrag; memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
	if(enviar((uint8_t*)ICMP_DATA,strlen(ICMP_DATA),pila_protocolos,&parametros_icmp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;
	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);

	//Luego, un paquete UDP
	//Definimos la pila de protocolos que queremos seguir
	pila_protocolos[0]=UDP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=ETH_PROTO;
	//Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
	Parametros parametros_udp; memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN); parametros_udp.bit_DF=flag_dontfrag; parametros_udp.puerto_destino=puerto_destino;
	//Enviamos
	if(enviar((uint8_t*)data,strlen(data),pila_protocolos,&parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;

	printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont,fichero_pcap_destino);
	
	//Cerramos descriptores
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);

	return OK;
}


/****************************************************************************************
 * Nombre: enviar                                                                       *
 * Descripcion: Esta funcion envia un mensaje                                           *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a enviar                                                          *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -longitud: bytes que componen mensaje                                               *
 *  -parametros: parametros necesario para el envio (struct parametros)                 *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint32_t longitud,uint16_t* pila_protocolos,void *parametros){
	uint16_t protocolo=pila_protocolos[0];
	printf("Enviar(%"PRIu16") %s %d.\n",protocolo,__FILE__,__LINE__);
	if(protocolos_registrados[protocolo]==NULL){
		printf("Protocolo %"PRIu16" desconocido\n",protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje,longitud,pila_protocolos,parametros);
	}
	return ERROR;
}


/***************************TODO Pila de protocolos a implementar************************************/


/****************************************************************************************
 * Nombre: moduloICMP                                                                   *
 * Descripcion: Esta funcion implementa el modulo de envio ICMP                         *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a anadir a la cabecera ICMP                                       *
 *  -longitud: bytes que componen el mensaje                                            *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t segmento[ICMP_DATAGRAM_MAX]={0};
	uint8_t aux8;
	uint16_t aux16;
	uint32_t pos=0;
	uint8_t protocolo_inferior=pila_protocolos[1];
	uint8_t *checksum = NULL;
	printf("modulo ICMP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if(longitud > (ICMP_DATAGRAM_MAX -ICMP_HLEN)){
		printf("Error, mensaje demasiado grande\n");
		return ERROR;
	}

	//Rellenamos el campo Tipo.
	aux8=PING_TIPO;
	memcpy(segmento+pos,&aux8,sizeof(uint8_t));
	pos+=sizeof(uint8_t);

	//Rellenamos el campo Código.
	aux8 = PING_CODE;
	memcpy(segmento+pos, &aux8, sizeof(uint8_t));
	pos += sizeof(uint8_t);

	//Rellenamos el campo Suma de Control.
	aux16 = 0;
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	//Rellenamos el campo Identificador.
	aux16 = htons(getpid());
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	//Rellenamos el campo Número de Secuencia.
	aux16 = htons(1);
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	//Rellenamos el mensaje.
	memcpy(segmento+pos, mensaje, longitud);

	//Calculamos el checksum y lo reescribimos.
	pos -= sizeof(uint16_t)*2;
	checksum = (uint8_t*)malloc(sizeof(uint16_t));
	if(calcularChecksum(segmento, longitud, checksum) == ERROR){
		return ERROR;
	}
	memcpy(segmento+pos, checksum, sizeof(uint16_t));
	free(checksum);

	//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,longitud+pos,pila_protocolos,parametros);
}


/****************************************************************************************
 * Nombre: moduloUDP                                                                    *
 * Descripcion: Esta funcion implementa el modulo de envio UDP                          *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a enviar                                                          *
 *  -longitud: bytes que componen mensaje                                               *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t segmento[UDP_SEG_MAX]={0};
	uint16_t puerto_origen = 0, suma_control=0;
	uint16_t aux16;
	uint32_t pos=0;
	uint8_t protocolo_inferior=pila_protocolos[1];
	printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if (longitud>UDP_SEG_MAX){
		printf("Error: mensaje demasiado grande para UDP (%d).\n",UDP_SEG_MAX);
		return ERROR;
	}

	Parametros udpdatos=*((Parametros*)parametros);
	uint16_t puerto_destino=udpdatos.puerto_destino;


	//Rellenamos el puerto origen.
	if(obtenerPuertoOrigen(&puerto_origen) == ERROR){
		printf("Error al obtener puerto origen\n");
			return ERROR;
	}
	aux16=htons(puerto_origen);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	//Rellenamos el puerto destino
	aux16 = htons(puerto_destino);
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	//Rellenamos la longitud.
	aux16 = htons(UDP_HLEN + longitud);
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	//Rellenamos el campo Checksum.
	memcpy(segmento+pos, &suma_control, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	//Rellenamos el mensaje.
	memcpy(segmento+pos, mensaje, longitud);

	//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,longitud+pos,pila_protocolos,parametros);
}


/****************************************************************************************
 * Nombre: moduloIP                                                                     *
 * Descripcion: Esta funcion implementa el modulo de envio IP                           *
 * Argumentos:                                                                          *
 *  -segmento: segmento a enviar                                                        *
 *  -longitud: bytes que componen el segmento                                           *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloIP(uint8_t* segmento, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t datagrama[IP_DATAGRAM_MAX]={0};
	uint32_t aux32;
	uint16_t aux16;
	uint8_t aux8;
	uint32_t pos=0,pos_control=0;
	uint8_t IP_origen[IP_ALEN];
	uint8_t protocolo_superior=pila_protocolos[0];
	uint8_t protocolo_inferior=pila_protocolos[2];
	pila_protocolos++;
	uint8_t mascara[IP_ALEN],IP_rango_origen[IP_ALEN],IP_rango_destino[IP_ALEN];
	uint16_t mtu;
	uint8_t *puerta_enlace;
	uint8_t *suma_control;
	uint16_t len_fragmento;
	int num_paquetes;
	int i;

	printf("modulo IP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);
	
	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* IP_destino=ipdatos.IP_destino;
	
	//Obtenemos la MTU.
	if(obtenerMTUInterface(interface, &mtu) == ERROR){
		return ERROR;
	}
	
	//Obtenemos la IP origen y la mascara de la interfaz y aplicamos la mascara a las IP origen y destino.
	if(obtenerIPInterface(interface, IP_origen) == ERROR){
		return ERROR;
	}
	
	if(obtenerMascaraInterface(interface, mascara) == ERROR){
		return ERROR;
	}
	
	if(aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen) == ERROR){
		return ERROR;
	}
	
	if(aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino) == ERROR){
		return ERROR;
	}
	
	//Comprobamos si la direccion destino esta en la misma subred que la direccion origen y realizamos el ARPrequest contingente.
	if((IP_rango_origen[0] == IP_rango_destino[0]) && (IP_rango_origen[1] == IP_rango_destino[1]) && (IP_rango_origen[2] == IP_rango_destino[2]) && (IP_rango_origen[3] == IP_rango_destino[3])){
		printf("La direccion de destino se encuentra en la misma subred que la direccion origen\n");
		
		if(solicitudARP(interface, IP_destino, ipdatos.ETH_destino) == ERROR){
			return ERROR;
		}
		
	}else{
		printf("La direccion de destino no se encuentra en la misma subred que la direccion de origen\n");
		
		//Obtenemos la puerta de enlace y realizamos el ARPrequest sobre la misma.
		puerta_enlace = (uint8_t*)malloc(IP_ALEN);
		if(obtenerGateway(interface, puerta_enlace) == ERROR){
			return ERROR;
		}
		
		if(solicitudARP(interface, puerta_enlace, ipdatos.ETH_destino) == ERROR){
			free(puerta_enlace);
			return ERROR;
		}
	}

	//Rellenamos la cabecera o cabeceras dependiendo si el paquete necesita fragmentacion o no.
	if(longitud > mtu - IP_HLEN){
		if(flag_dontfrag == 1){
			printf("Error: El paquete necesita fragmentacion pero se ha solicitado que no se fragmente (-d)\n");
			return ERROR;
		}
		printf("El paquete es demasiado grande, necesita fragmentacion\n");
		
		//Calculamos el numero de fragmentos.
		num_paquetes = ceil(longitud*1.0/(mtu - IP_HLEN));
		
		for(i = 0; i < num_paquetes; i++){
			memset(datagrama, 0, IP_DATAGRAM_MAX);

			//Concatenamos el valor de version y ihl para copiarlos en una sola vez. 
			//En este caso la version siempre sera 4 y la longitud 6.
			aux8 = 0x46;
			memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
			pos += sizeof(uint8_t);
			
			//Rellenamos el tipo de servicio, en nuestro caso será el rutinario.
			aux8 = 0;
			memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
			pos += sizeof(uint8_t);
			
			//Rellenamos la longitud total, al estar el paquete fragmentado se rellena con la longitud del fragmento.
			//En nuestro caso (Ethernet), la longitud es siempre 1500 excepto en el ultimo fragmento.
			
			if(i == num_paquetes - 1){
				len_fragmento = longitud - (num_paquetes - 1)*(floor((mtu - IP_HLEN)/8)*8) + IP_HLEN;
				
			}else{
				len_fragmento = floor((mtu - IP_HLEN)/8)*8 + IP_HLEN;
				
			}
	
			aux16 = htons(len_fragmento);
			memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
			pos += sizeof(uint16_t);
			
			//Rellenamos el identificador.
			aux16 = htons(cont + 1);
			memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
			pos += sizeof(uint16_t);
			
			//Rellenamos las flags y posicion. Para el ultimo fragmento los bits de flags seran 000 y para los demás 001.
			//La posicion sera el numero de bytes del fragmento sin contar la cabecera.
			aux16 = (floor((mtu - IP_HLEN)/8)*8*i)/8;
			if(i == num_paquetes - 1){
				aux16 = htons(0x0000 | aux16);
			
			}else{
				aux16 = htons(0x2000 | aux16);
				
			}
			
			memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
			pos += sizeof(uint16_t);
			
			//Rellenamos tiempo de vida.
			aux8 = 64;
			memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
			pos += sizeof(uint8_t);
			
			//Rellenamos el protocolo de nivel superior.
			memcpy(datagrama+pos, &protocolo_superior, sizeof(uint8_t));
			pos += sizeof(uint8_t);
			
			//Rellenamos el checksum por primera vez todo a 0.
			pos_control = pos;
			aux16 = 0;
			memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
			pos += sizeof(uint16_t);
			
			//Rellenamos la direccion IP origen.
			memcpy(datagrama+pos, IP_origen, sizeof(uint32_t));
			pos += sizeof(uint32_t);
			
			//Rellenamos la direccion IP destino.
			memcpy(datagrama+pos, IP_destino, sizeof(uint32_t));
			pos += sizeof(uint32_t);		
			
			//Rellenaos los campos de opciones y relleno todos a 0.
			aux32 = 0;
			memcpy(datagrama+pos, &aux32, sizeof(uint32_t));
			pos += sizeof(uint32_t);
			
			//Calculamos el checksum final.
			suma_control = (uint8_t*)malloc(sizeof(uint16_t));
			if(calcularChecksum(datagrama, IP_HLEN, suma_control) == ERROR){
				return ERROR;
			}
			
			memcpy(datagrama+pos_control, suma_control, sizeof(uint16_t));
			free(suma_control);
			
			//Rellenamos despues del datagrama los maximos bytes posibles del segmento, 1476 (mtu - IP_HLEN).
			memcpy(datagrama+pos, segmento+(mtu - IP_HLEN)*i, len_fragmento - IP_HLEN);
			pos = pos + len_fragmento - IP_HLEN;
			
			if(i == num_paquetes - 1){
				return protocolos_registrados[protocolo_inferior](datagrama,len_fragmento,pila_protocolos,&ipdatos);
				
			}else{
				if(protocolos_registrados[protocolo_inferior](datagrama,len_fragmento,pila_protocolos,&ipdatos) == ERROR){
					return ERROR;
				}
			}
				
			
		}
		
				
	}else{
		printf("El paquete no necesita fragmentacion\n");
		
		num_paquetes = 1;
		
		//Concatenamos el valor de version y ihl para copiarlos en una sola vez. 
		//En este caso la version siempre sera 4 y la longitud 6.
		aux8 = 0x46;
		memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		
		//Rellenamos el tipo de servicio, en nuestro caso será el rutinario.
		aux8 = 0;
		memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		
		//Rellenamos la longitud total.
		aux16 = htons(longitud + IP_HLEN);
		memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
		pos += sizeof(uint16_t);
		
		//Rellenamos el identificador.
		aux16 = htons(cont + 1);
		memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
		pos += sizeof(uint16_t);
		
		//Rellenamos flags y posicion a la vez, marcando a 1 el bit de divisibilidad de las flags (bit 1) y dejando a 0 la posicion.
		aux16 = 0;
		aux16 = htons(0x4000 | aux16);
		memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
		pos += sizeof(uint16_t);
		
		//Rellenamos tiempo de vida.
		aux8 = 64;
		memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		
		//Rellenamos el protocolo de nivel superior.
		memcpy(datagrama+pos, &protocolo_superior, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		
		//Rellenamos el checksum por primera vez todo a 0.
		pos_control = pos;
		aux16 = 0;
		memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
		pos += sizeof(uint16_t);
		
		//Rellenamos la direccion IP origen.
		memcpy(datagrama+pos, IP_origen, sizeof(uint32_t));
		pos += sizeof(uint32_t);
		
		//Rellenamos la direccion IP destino.
		memcpy(datagrama+pos, IP_destino, sizeof(uint32_t));
		pos += sizeof(uint32_t);		
		
		//Rellenaos los campos de opciones y relleno todos a 0.
		aux32 = 0;
		memcpy(datagrama+pos, &aux32, sizeof(uint32_t));
		pos += sizeof(uint32_t);
		
		//Calculamos el checksum final.
		suma_control = (uint8_t*)malloc(sizeof(uint16_t));
		if(calcularChecksum(datagrama, IP_HLEN, suma_control) == ERROR){
			return ERROR;
		}
		
		memcpy(datagrama+pos_control, suma_control, sizeof(uint16_t));
		free(suma_control);
		
		//Rellenamos el segmento.
		memcpy(datagrama+pos, segmento, longitud);
		
		return protocolos_registrados[protocolo_inferior](datagrama,longitud+pos,pila_protocolos,&ipdatos);
	}
	
	return ERROR;
}


/****************************************************************************************
 * Nombre: moduloETH                                                                    *
 * Descripcion: Esta funcion implementa el modulo de envio Ethernet                     *
 * Argumentos:                                                                          *
 *  -datagrama: datagrama a enviar                                                      *
 *  -longitud: bytes que componen el datagrama                                          *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: Parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint32_t longitud, uint16_t* pila_protocolos,void *parametros){
	//TODO
	//[...] Variables del modulo
	uint8_t trama[ETH_FRAME_MAX]={0};
	uint32_t pos = 0;
	uint8_t *eth_origen;
	uint8_t *eth_destino;
	uint16_t aux16;
	struct pcap_pkthdr header;
	struct timeval time;

	pila_protocolos++;

	printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);

	if(obtenerMTUInterface(interface, &aux16) == ERROR){
		printf("Error al obtener tamaño máximo de transferencia \n");
		return ERROR;
	}

	if(longitud > aux16){
		printf("El mensaje supera el tamaño maximo\n");
		return ERROR;
	}


	//Rellenaos la direción ETH destino.
	Parametros ethdatos = *(Parametros*)parametros;
	eth_destino = ethdatos.ETH_destino;
	memcpy(trama+pos, eth_destino, ETH_ALEN);
	pos += ETH_ALEN;

	//Rellenamos la dirección ETH origen
	eth_origen = (uint8_t*)malloc(sizeof(uint8_t)*ETH_ALEN);
	if(obtenerMACdeInterface(interface, eth_origen) == ERROR){
		printf("Error al obtener la direcion ETH origen\n");
		return ERROR;
	}
	memcpy(trama+pos, eth_origen, ETH_ALEN);
	free(eth_origen);
	pos += ETH_ALEN;

	//Rellenamos el tipo ethernet.
	aux16 = htons(IP_PROTO);
	memcpy(trama+pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	//Rellenamos el datagrama.
	memcpy(trama+pos, datagrama, longitud);

	//Enviamos el paquete.
	pcap_inject(descr, (const u_char*)trama, longitud+pos);

	//Almacenamos la salida por cuestiones de debugging [...]
	gettimeofday(&time, NULL);
	header.ts = time;
	header.caplen = longitud+pos;
	header.len = longitud+pos;
	pcap_dump((uint8_t*)pdumper, &header, trama);

	//Mostramos el contenido del paquete en hexadecimal si nos lo indican al ejecutar el programa.
	printf("\n");
	if(flag_mostrar == 1){
		mostrarHex(trama, longitud+pos);
	}
	printf("\n");
	
	return OK;
}



/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
 * Nombre: aplicarMascara                                                               *
 * Descripcion: Esta funcion aplica una mascara a una vector                            *
 * Argumentos:                                                                          *
 *  -IP: IP a la que aplicar la mascara en orden de red                                 *
 *  -mascara: mascara a aplicar en orden de red                                         *
 *  -longitud: bytes que componen la direccion (IPv4 == 4)                              *
 *  -resultado: Resultados de aplicar mascara en IP en orden red                        *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint8_t longitud, uint8_t* resultado){
	int i;

	if(IP == NULL || mascara == NULL){
		return ERROR;
	}

	for(i = 0; i < longitud; i++){
		resultado[i] = IP[i] & mascara[i];
	}

	return OK;
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
 * Nombre: mostrarHex                                                                   *
 * Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector              *
 * Argumentos:                                                                          *
 *  -datos: bytes que conforman un mensaje                                              *
 *  -longitud: Bytes que componen el mensaje                                            *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t mostrarHex(uint8_t * datos, uint32_t longitud){
	uint32_t i;
	printf("Datos:\n");
	for (i=0;i<longitud;i++){
		printf("%02"PRIx8" ", datos[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
 * Nombre: calcularChecksum                                                             *
 * Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP           *
 * Argumentos:                                                                          *
 *   -datos: datos sobre los que calcular el checksum                                   *
 *   -longitud: numero de bytes de los datos sobre los que calcular el checksum         *
 *   -checksum: checksum de los datos (2 bytes) en orden de red!                        *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t calcularChecksum(uint8_t *datos, uint16_t longitud, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum=0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (uint32_t)word16;
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
 * Nombre: inicializarPilaEnviar                                                        *
 * Descripcion: inicializar la pila de red para enviar registrando los distintos modulos*
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados,MAX_PROTOCOL*sizeof(pf_notificacion));

	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados)==ERROR)
		return ERROR;

	return OK;
}


/****************************************************************************************
 * Nombre: registrarProtocolo                                                           *
 * Descripcion: Registra un protocolo en la tabla de protocolos                         *
 * Argumentos:                                                                          *
 *  -protocolo: Referencia del protocolo (ver RFC 1700)                                 *
 *  -handleModule: Funcion a llamar con los datos a enviar                              *
 *  -protocolos_registrados: vector de funciones registradas                            *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados==NULL ||  handleModule==NULL){
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo]=handleModule;
	return OK;
}
