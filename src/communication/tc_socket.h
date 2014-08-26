#ifndef TC_SOCKET_INCLUDED
#define TC_SOCKET_INCLUDED

#define TC_INVALID_SOCK -1

#include <xcopy.h>

#define tc_socket_close(fd) close(fd)

int tc_pcap_socket_in_init(pcap_t **pd, char *device, 
        int snap_len, int buf_size, char *pcap_filter);
int tc_pcap_snd_init(char *if_name, int mtu);
int tc_pcap_snd(unsigned char *frame, size_t len);
int tc_pcap_over(void);

#endif /* TC_SOCKET_INCLUDED */

