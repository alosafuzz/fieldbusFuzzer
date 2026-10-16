/* Isolate: does libscpi's SCPI_Input hang when fed a payload in 10-byte chunks
   (as the test-tcp server does, smbuffer[10]), with NO re-init between "connections"?
   If this hangs -> libscpi (incremental-feed / persistent-state) bug.
   If it returns -> the hang is in the server loop, not libscpi. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "scpi/scpi.h"
#include "scpi-def.h"
size_t SCPI_Write(scpi_t*c,const char*d,size_t n){(void)c;(void)d;return n;}
scpi_result_t SCPI_Flush(scpi_t*c){(void)c;return SCPI_RES_OK;}
int SCPI_Error(scpi_t*c,int_fast16_t e){(void)c;(void)e;return 0;}
scpi_result_t SCPI_Control(scpi_t*c,scpi_ctrl_name_t n,scpi_reg_val_t v){(void)c;(void)n;(void)v;return SCPI_RES_OK;}
scpi_result_t SCPI_Reset(scpi_t*c){(void)c;return SCPI_RES_OK;}
scpi_result_t SCPI_SystemCommTcpipControlQ(scpi_t*c){(void)c;return SCPI_RES_OK;}
int main(int argc,char**argv){
    FILE*f=fopen(argv[1],"rb"); fseek(f,0,SEEK_END); long L=ftell(f); fseek(f,0,SEEK_SET);
    char*buf=malloc(L); fread(buf,1,L,f); fclose(f);
    SCPI_Init(&scpi_context,scpi_commands,&scpi_interface,scpi_units_def,
      SCPI_IDN1,SCPI_IDN2,SCPI_IDN3,SCPI_IDN4,
      scpi_input_buffer,SCPI_INPUT_BUFFER_LENGTH,scpi_error_queue_data,SCPI_ERROR_QUEUE_SIZE);
    /* feed in 10-byte chunks like the server */
    long i; for(i=0;i<L;i+=10){ int n=(L-i<10)?(int)(L-i):10; SCPI_Input(&scpi_context,buf+i,n); }
    fprintf(stderr,"case payload fed OK\n");
    /* now a follow-up *IDN? on the SAME context (no re-init), like the next connection */
    const char*idn="*IDN?\n"; SCPI_Input(&scpi_context,idn,6);
    fprintf(stderr,"follow-up IDN fed OK -> NO HANG\n");
    return 0;
}
