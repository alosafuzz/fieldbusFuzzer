/* Wire-style delivery of the whole corpus to libscpi IN-PROCESS: one persistent
   SCPI context (like a long-lived connection/session), every corpus file fed in
   10-byte chunks (like the server's smbuffer[10]), under ASan/UBSan, with a SIGALRM
   hang watchdog. Isolates libscpi's incremental-input + persistent-state path from
   the (flaky) example server. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include "scpi/scpi.h"
#include "scpi-def.h"
size_t SCPI_Write(scpi_t*c,const char*d,size_t n){(void)c;(void)d;return n;}
scpi_result_t SCPI_Flush(scpi_t*c){(void)c;return SCPI_RES_OK;}
int SCPI_Error(scpi_t*c,int_fast16_t e){(void)c;(void)e;return 0;}
scpi_result_t SCPI_Control(scpi_t*c,scpi_ctrl_name_t n,scpi_reg_val_t v){(void)c;(void)n;(void)v;return SCPI_RES_OK;}
scpi_result_t SCPI_Reset(scpi_t*c){(void)c;return SCPI_RES_OK;}
scpi_result_t SCPI_SystemCommTcpipControlQ(scpi_t*c){(void)c;return SCPI_RES_OK;}
static volatile const char* cur="(none)";
static void on_alarm(int s){(void)s; dprintf(2,"\n[HANG] watchdog fired on file: %s\n",cur); _exit(124);}
int main(int argc,char**argv){
    signal(SIGALRM,on_alarm);
    SCPI_Init(&scpi_context,scpi_commands,&scpi_interface,scpi_units_def,
      SCPI_IDN1,SCPI_IDN2,SCPI_IDN3,SCPI_IDN4,
      scpi_input_buffer,SCPI_INPUT_BUFFER_LENGTH,scpi_error_queue_data,SCPI_ERROR_QUEUE_SIZE);
    const char*dir=argv[1]; DIR*d=opendir(dir); struct dirent*e; long nfiles=0;
    char path[4096];
    while((e=readdir(d))){
        if(e->d_name[0]=='.') continue;
        snprintf(path,sizeof path,"%s/%s",dir,e->d_name); cur=e->d_name;
        FILE*f=fopen(path,"rb"); if(!f) continue;
        fseek(f,0,SEEK_END); long L=ftell(f); fseek(f,0,SEEK_SET);
        char*buf=malloc(L?L:1); if(L)fread(buf,1,L,f); fclose(f);
        alarm(10);                               /* per-file hang watchdog */
        long i; for(i=0;i<L;i+=10){ int n=(L-i<10)?(int)(L-i):10; SCPI_Input(&scpi_context,buf+i,n); }
        alarm(0); free(buf); nfiles++;
    }
    closedir(d);
    fprintf(stderr,"[OK] fed %ld files chunked on a persistent context, no hang/crash\n",nfiles);
    return 0;
}
