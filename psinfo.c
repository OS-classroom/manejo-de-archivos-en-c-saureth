#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void Etapa1(char *PID);
void Etapa2(char *argv[]);
void Etapa3(char *argv[]);
int CheckPID(char *PID);
int CountParamAmount(char *argv[]);
int PrintParamError(int type, char* PID);

struct processInfo{
    char Name[256];
    char State[256];
    char VmData[256];
    char VmStk[256];
    char VmExe[256];
    char vcs[256];
    char nvcs[256];
};
typedef struct processInfo pInfo;

int main(int argc, char*argv[])
{      
    int paramAmount = CountParamAmount(argv);
    
    int errorCode = -1;

    if (paramAmount==1){
	errorCode = PrintParamError(paramAmount, argv[0]);
    }
    else if(strcmp (argv[1],"-l")==0){
	Etapa2(argv);	
    }       
    else if(strcmp (argv[1],"-r")==0){
	Etapa3(argv);	
    } 
    else{
	    if (paramAmount==2){
		char *PID;    
		PID = argv[1];
		Etapa1(PID);	
	    }
	    else {
		errorCode = PrintParamError(paramAmount, argv[1]);
		return errorCode;
	    }
    }
}

int PrintParamError(int type, char *PID){
    int t =-1;
    if (type==2){
	t = 1;
	printf("Error: Código %d: ", t);
	printf("No se encontró el proceso con PID: %s\n", PID);	
    }
    else if(type<2){
	t = 2;
	printf("Error: Código %d: ", t);
	printf("Faltan parámetros \n");
	
    }
    else if (type>2){
	t = 3;
	printf("Error: Código %d: ", t);
	printf("Parámetros inválidos \n");	
    }     
    printf("	Si quiere listar varios procesos, utilice la opción -l .\n");
    printf("	Si quiere un reporte, utilice la opción -r .\n");
    printf("	De lo contrario, sólo debería escribir un parámetro\n");
    printf("	el cual es el PID de un proceso vigente, es decir, un número.\n");
    return t;
}

int CountParamAmount(char *argv[]){
    int it = 0;
    while(argv[it]!= 0){
	it++;
    }
    return it;
}

int CheckPID(char *PID){
    char procRoute[20] = "/proc/";
    strcat(procRoute,PID); 
    strcat(procRoute,"/status");
    
    FILE *fd = fopen(procRoute,"r");	
    	
    if (fd == NULL){
	//printf(" No se encontró el proceso %s\n", PID);
	return 0;
    }
    fclose(fd);
    return 1;
}

void Etapa3(char *argv[]){
    int iterator = 2;
    pInfo *pi1;
    char *kB = "kB";
    int it = 2;
    char n[256] = "psinfo-report";
    while(argv[it]!= 0){
	strcat(n,"-"); 
    	strcat(n,argv[it]); 
	it++;
    }
    strcat(n,".info");
    char fileName[256] = "--";
    strcpy(fileName , n);
    FILE *data = fopen(n,"w");
    if (data!= NULL){	
	    while(argv[iterator]!= 0){
	    	    pi1 = (pInfo*)malloc(sizeof(pInfo));
		    char *PID;    
		    PID = argv[iterator];
		    strcpy(PID,argv[iterator]);

		    char procRoute[20] = "/proc/";
		    strcat(procRoute,PID); 
		    strcat(procRoute,"/status");
		    if(CheckPID(PID)==1){
			fprintf(data,"---Proceso número %d ---\n", (iterator-1));
			FILE *fd = fopen(procRoute,"r");
			strcpy(pi1->Name , "Name:");
			strcpy(pi1->State , "State:");
			strcpy(pi1->VmData , "VmData:");
			strcpy(pi1->VmStk , "VmStk:");
			strcpy(pi1->VmExe , "VmExe:");
			strcpy(pi1->vcs , "voluntary_ctxt_switches:");
			strcpy(pi1->nvcs , "nonvoluntary_ctxt_switches:");
			int finished = 0;
			char procLine[200];
			int counter =0;	
			char regSize[256];
			int dSize = 0;	
			int sSize= 0;	
			int tSize = 0;
			int totalSize = 0;
			while(finished==0&& counter <126){	
				fscanf(fd,"%s", procLine);
				if(strcmp (procLine,pi1->Name)==0){	
					fprintf(data,"%s ", "Nombre:");
					fscanf(fd,"%s ", procLine);				
					fprintf(data,"%s \n", procLine);			
				}
				else if(strcmp (procLine,pi1->State)==0){	
					fprintf(data,"%s ", "Estado:");
					fscanf(fd,"%s ", procLine);
					fprintf(data,"%s ", procLine);
					fscanf(fd,"%s ", procLine);					
					fprintf(data,"%s \n", procLine);
				}	
				else if(strcmp (procLine,pi1->VmData)==0){	
					fscanf(fd,"%s ", procLine);
					strcpy(regSize, procLine);
					fscanf(fd,"%s ", procLine);
					sscanf(regSize,"%d",&dSize);
				}
				else if(strcmp (procLine,pi1->VmStk)==0){	
					fscanf(fd,"%s ", procLine);
					strcpy(regSize, procLine);
					fscanf(fd,"%s ", procLine);	
					sscanf(regSize,"%d",&sSize);
				}
				else if(strcmp (procLine,pi1->VmExe)==0){	
					fscanf(fd,"%s ", procLine);
					strcpy(regSize, procLine);
					fscanf(fd,"%s ", procLine);	
					sscanf(regSize,"%d",&tSize);
					totalSize= dSize+sSize+tSize;
					fprintf(data,"Tamaño total de la imagen de memoria: %d \n", totalSize);
					fprintf(data,"	Tamaño de la región TEXT: %d %s\n", tSize,kB);
					fprintf(data,"	Tamaño de la región DATA: %d %s\n", dSize,kB);
					fprintf(data,"	Tamaño de la región STACK: %d %s\n", sSize,kB);
				}
				else if(strcmp (procLine,pi1->vcs)==0){	
					fprintf(data,"Cambios de contexto voluntarios: ");
					fscanf(fd,"%s ", procLine);
					fprintf(data,"%s \n", procLine);
				}
				else if(strcmp (procLine,pi1->nvcs)==0){	
					fprintf(data,"Cambios de contexto involuntarios: ");
					fscanf(fd,"%s ", procLine);
					fprintf(data,"%s \n", procLine);
					finished = 1;		
				}		
				counter++;			
			    }
		    	    fclose(fd);	
			    fprintf(data,"---Fin proceso número %d ---\n", (iterator-2));		    
		} 
		else{
		    fprintf(data, "No se encontró el proceso %s\n", PID);
		    PrintParamError(2, PID);
		}
		iterator++;	
		free(pi1);
		fprintf(data,"\n"); 
    	}
	fclose(data);   		
        printf("Archivo guardado con nombre:  %s \n", fileName);	
    }
    else{
	printf("No se pudo crear el archivo. Error de I/O  \n");	
    }    
}

void Etapa2(char *argv[]){
    int iterator = 2;
    pInfo *pi1;
    char *kB = "kB";
    while(argv[iterator]!= 0){
	    
    	    pi1 = (pInfo*)malloc(sizeof(pInfo));
	    char *PID;    
	    PID = argv[iterator];
	    strcpy(PID,argv[iterator]);

	    char procRoute[20] = "/proc/";
	    strcat(procRoute,PID); 
	    strcat(procRoute,"/status");
	    	
	    if (CheckPID(PID) != 0){
		printf("---Proceso número %d ---\n", (iterator-1));
		FILE *fd = fopen(procRoute,"r");				
		strcpy(pi1->Name , "Name:");
		strcpy(pi1->State , "State:");
		strcpy(pi1->VmData , "VmData:");
		strcpy(pi1->VmStk , "VmStk:");
		strcpy(pi1->VmExe , "VmExe:");
		strcpy(pi1->vcs , "voluntary_ctxt_switches:");
		strcpy(pi1->nvcs , "nonvoluntary_ctxt_switches:");
	
		int finished = 0;
		char procLine[200];
		int counter =0;	

		char regSize[256];
		int dSize = 0;	
		int sSize= 0;	
		int tSize = 0;
		int totalSize = 0;
		while(finished==0&& counter <126){	
			fscanf(fd,"%s", procLine);
			if(strcmp (procLine,pi1->Name)==0){	
				printf("%s ", "Nombre:");
				fscanf(fd,"%s ", procLine);				
				printf("%s \n", procLine);			
			}
			else if(strcmp (procLine,pi1->State)==0){	
				printf("%s ", "Estado:");
				fscanf(fd,"%s ", procLine);
				printf("%s ", procLine);
				fscanf(fd,"%s ", procLine);					
				printf("%s \n", procLine);
			}	
			else if(strcmp (procLine,pi1->VmData)==0){	
				fscanf(fd,"%s ", procLine);
				strcpy(regSize, procLine);
				fscanf(fd,"%s ", procLine);
				sscanf(regSize,"%d",&dSize);
			}
			else if(strcmp (procLine,pi1->VmStk)==0){	
				fscanf(fd,"%s ", procLine);
				strcpy(regSize, procLine);
				fscanf(fd,"%s ", procLine);	
				sscanf(regSize,"%d",&sSize);
			}
			else if(strcmp (procLine,pi1->VmExe)==0){	
				fscanf(fd,"%s ", procLine);
				strcpy(regSize, procLine);
				fscanf(fd,"%s ", procLine);	
				sscanf(regSize,"%d",&tSize);
				totalSize= dSize+sSize+tSize;
				printf("Tamaño total de la imagen de memoria: %d \n", totalSize);
				printf("	Tamaño de la región TEXT: %d %s\n", tSize,kB);
				printf("	Tamaño de la región DATA: %d %s\n", dSize,kB);
				printf("	Tamaño de la región STACK: %d %s\n", sSize,kB);
			}
			else if(strcmp (procLine,pi1->vcs)==0){	
				printf("Cambios de contexto voluntarios: ");
				fscanf(fd,"%s ", procLine);
				printf("%s \n", procLine);
			}
			else if(strcmp (procLine,pi1->nvcs)==0){	
				printf("Cambios de contexto involuntarios: ");
				fscanf(fd,"%s ", procLine);
				printf("%s \n", procLine);
				finished = 1;		
			}		
			counter++;
		}    	    
		fclose(fd);	
	        printf("---Fin proceso número %d ---\n", (iterator-1));    	
	    }    
	    else {
		PrintParamError(2,PID);
	    }
	    iterator++;	
    	    free(pi1);
	    printf("\n");
    }
}

void Etapa1(char *PID){
    char procRoute[20] = "/proc/";
    strcat(procRoute,PID); 
    strcat(procRoute,"/status");
    FILE *fd = fopen(procRoute,"r");
    if (fd == NULL){
	//printf(" No se encontró el proceso %s\n", PID);
    	PrintParamError(2,PID);
	return;
    }	
        
    else{
	char *Name = "Name:";
	char *State = "State:";
	char *VmData = "VmData:";
	char *VmStk = "VmStk:";
	char *VmExe = "VmExe:";
	char *vcs = "voluntary_ctxt_switches:";
	char *nvcs = "nonvoluntary_ctxt_switches:";
	int finished = 0;
	char procLine[200];
	int counter =0;	

	char regSize[256];
	int dSize = 0;	
	int sSize= 0;	
	int tSize = 0;
	int totalSize = 0;
	while(finished==0&& counter <126){
		fscanf(fd,"%s", procLine);
		if(strcmp (procLine,Name)==0){	
			printf("%s ", "Nombre:");
			fscanf(fd,"%s ", procLine);				
			printf("%s \n", procLine);			
		}
		else if(strcmp (procLine,State)==0){	
			printf("%s ", "Estado:");
			fscanf(fd,"%s ", procLine);
			printf("%s ", procLine);
			fscanf(fd,"%s ", procLine);					
			printf("%s \n", procLine);
		}	
		else if(strcmp (procLine,VmData)==0){	
			fscanf(fd,"%s ", procLine);
			strcpy(regSize, procLine);
			fscanf(fd,"%s ", procLine);	
			sscanf(regSize,"%d",&dSize);
		}
		else if(strcmp (procLine,VmStk)==0){	
			fscanf(fd,"%s ", procLine);
			strcpy(regSize, procLine);
			fscanf(fd,"%s ", procLine);	
			sscanf(regSize,"%d",&sSize);
		}
		else if(strcmp (procLine,VmExe)==0){	
			fscanf(fd,"%s ", procLine);
			strcpy(regSize, procLine);
			fscanf(fd,"%s ", procLine);	
			sscanf(regSize,"%d",&tSize);
			totalSize= dSize+sSize+tSize;
			printf("Tamaño total de la imagen de memoria: %d \n", totalSize);
			printf("	Tamaño de la región TEXT: %d \n", tSize);
			printf("	Tamaño de la región DATA: %d \n", dSize);
			printf("	Tamaño de la región STACK: %d \n", sSize);
		}
		else if(strcmp (procLine,vcs)==0){	
			printf("Cambios de contexto voluntarios: ");
			fscanf(fd,"%s ", procLine);
			printf("%s \n", procLine);
		}
		else if(strcmp (procLine,nvcs)==0){	
			printf("Cambios de contexto involuntarios: ");
			fscanf(fd,"%s ", procLine);
			printf("%s \n", procLine);
			finished = 1;		
		}
		counter++;
	}
	fclose(fd);
    }
}
	
