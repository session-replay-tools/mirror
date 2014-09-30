#ifndef  TC_UTIL_INCLUDED
#define  TC_UTIL_INCLUDED

#include <xcopy.h>

int retrieve_devices(char *raw_device, devices_t *devices);
int get_l2_len(const unsigned char *, const int);
unsigned char *get_ip_data(pcap_t *, unsigned char *, const int, int *);


static inline void 
fill_frame(struct ethernet_hdr *hdr, unsigned char *smac, unsigned char *dmac)
{
    memcpy(hdr->ether_shost, smac, ETHER_ADDR_LEN);
    memcpy(hdr->ether_dhost, dmac, ETHER_ADDR_LEN);
    hdr->ether_type = htons(ETH_P_IP); 
}

#endif   /* ----- #ifndef TC_UTIL_INCLUDED  ----- */

