/* Harness driver: stand up Keysight's real VXI-11 server (libHppVxi11Server) under
   qemu-aarch64, then idle so its RPC worker thread serves. Fuzz it over the wire with
   scpi_wire_rig.py / python-vxi11 / the icsScanner VXI-11 portmapper probe. */
#include <stdio.h>
#include <unistd.h>
extern int inet_start_VXI11_server(void);
int main(void){
    fprintf(stderr,"[harness] calling inet_start_VXI11_server()\n"); fflush(stderr);
    int r = inet_start_VXI11_server();
    fprintf(stderr,"[harness] inet_start_VXI11_server() returned %d; serving...\n", r); fflush(stderr);
    for(;;) sleep(3600);
    return 0;
}
