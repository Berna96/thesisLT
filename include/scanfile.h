#include "utility.h"
typedef struct ports_infos{
	int num_ports;
	char** port;
} ports_info;


ports_info* scan_file(FILE* file){
        char buffer_tmp[101];
        int index=0;
        int int_index=0;
	int len_ports=0;
        ports_info *ports;
	unsigned int len_buf=0;
	char * buffer;  
	ports=(ports_info *)ec_malloc(sizeof(ports_info));
       
	while(!feof(file)){
                if (fgets(buffer_tmp,100,file)==NULL)       break;
		len_buf=len_buf+strlen(buffer_tmp);	
        }
				//ATTENZIONE: il buffer contiene come ultimo carattere \n e quindi la 
				//lunghezza vera è len(buff)-1
	
	buffer=ec_malloc(sizeof(char)*(len_buf));
	fseek(file, 0, SEEK_SET);
	while(!feof(file)){
                if (fgets(buffer_tmp,100,file)==NULL)       break;
		strcat(buffer,buffer_tmp);
        }

	*(buffer+len_buf-1)='\0';
	len_buf--;
	//calcolo del numero di porte
        for(int i=0; i<len_buf;i++){
                if(buffer[i]==';')      ports->num_ports++;
        }
	
	//prima allocazione
        ports->port=(char **)ec_malloc(sizeof(char *)*(ports->num_ports+1));
	*(ports->port+ports->num_ports)='\0';
	//calcolo lunghezza delle porte e allocazione
        for(int i=0; i<len_buf;i++){
                if(buffer[i]!=';'){
                        len_ports++;
                }else{
                        *(ports->port+index)=(char *)ec_malloc(sizeof(char)*(len_ports+1));
                        *(*(ports->port+index)+len_ports)='\0';
			index++;
                        len_ports=0;

                }
        }
        index=0;
	int_index=0;
	
	//inizializzazione
        for(int i=0; i<len_buf;i++){
                if(buffer[i]!=';'){
                        *(*(ports->port+index)+int_index)=buffer[i];
                        int_index++;
                }else{
			index++;
			int_index=0;	
                }      
        }

	return ports;
}
