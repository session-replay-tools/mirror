 
#include <xcopy.h>


static int
tc_pcap_open(pcap_t **pd, char *device, int snap_len, int buf_size)
{
    int    status;
    char   ebuf[PCAP_ERRBUF_SIZE]; 

    *ebuf = '\0';

    *pd = pcap_create(device, ebuf);
    if (*pd == NULL) {
        tc_log_info(LOG_ERR, 0, "pcap create error:%s", ebuf);
        return TC_ERR;
    }

    status = pcap_set_snaplen(*pd, snap_len);
    if (status != 0) {
        tc_log_info(LOG_ERR, 0, "pcap_set_snaplen error:%s",
                pcap_statustostr(status));
        return TC_ERR;
    }

    status = pcap_set_promisc(*pd, 0);
    if (status != 0) {
        tc_log_info(LOG_ERR, 0, "pcap_set_promisc error:%s",
                pcap_statustostr(status));
        return TC_ERR;
    }

    status = pcap_set_timeout(*pd, 10);
    if (status != 0) {
        tc_log_info(LOG_ERR, 0, "pcap_set_timeout error:%s",
                pcap_statustostr(status));
        return TC_ERR;
    }

    status = pcap_set_buffer_size(*pd, buf_size);
    if (status != 0) {
        tc_log_info(LOG_ERR, 0, "pcap_set_buffer_size error:%s",
                pcap_statustostr(status));
        return TC_ERR;
    }

    tc_log_info(LOG_NOTICE, 0, "pcap_set_buffer_size:%d", buf_size);

    status = pcap_activate(*pd);
    if (status < 0) {
        tc_log_info(LOG_ERR, 0, "pcap_activate error:%s",
                pcap_statustostr(status));
        return TC_ERR;

    } else if (status > 0) {
        tc_log_info(LOG_WARN, 0, "pcap activate warn:%s", 
                pcap_statustostr(status));
    }

    return TC_OK;
}


int
tc_pcap_socket_in_init(pcap_t **pd, char *device, 
        int snap_len, int buf_size, char *pcap_filter)
{
    int         fd;
    char        ebuf[PCAP_ERRBUF_SIZE]; 
    struct      bpf_program fp;
    bpf_u_int32 net, netmask;      

    if (device == NULL) {
        return TC_INVALID_SOCK;
    }

    tc_log_info(LOG_NOTICE, 0, "pcap open,device:%s", device);

    *ebuf = '\0';

    if (tc_pcap_open(pd, device, snap_len, buf_size) == TC_ERR) {
        return TC_INVALID_SOCK;
    }

    if (pcap_lookupnet(device, &net, &netmask, ebuf) < 0) {
        net = 0;
        netmask = 0;
        tc_log_info(LOG_WARN, 0, "lookupnet:%s", ebuf);
        return TC_INVALID_SOCK;
    }

    if (pcap_compile(*pd, &fp, pcap_filter, 0, netmask) == -1) {
        tc_log_info(LOG_ERR, 0, "couldn't parse filter %s: %s", 
                pcap_filter, pcap_geterr(*pd));
        return TC_INVALID_SOCK;
    }

    if (pcap_setfilter(*pd, &fp) == -1) {
        tc_log_info(LOG_ERR, 0, "couldn't install filter %s: %s",
                pcap_filter, pcap_geterr(*pd));
        pcap_freecode(&fp);
        return TC_INVALID_SOCK;
    }

    pcap_freecode(&fp);

    if (pcap_get_selectable_fd(*pd) == -1) {
        tc_log_info(LOG_ERR, 0, "pcap_get_selectable_fd fails"); 
        return TC_INVALID_SOCK;
    }

    if (pcap_setnonblock(*pd, 1, ebuf) == -1) {
        tc_log_info(LOG_ERR, 0, "pcap_setnonblock failed: %s", ebuf);
        return TC_INVALID_SOCK;
    }

    fd = pcap_get_selectable_fd(*pd);

    return fd;
}


static pcap_t *pcap = NULL;

int
tc_pcap_snd_init(char *if_name, int mtu)
{
    char  pcap_errbuf[PCAP_ERRBUF_SIZE];

    pcap_errbuf[0] = '\0';
    pcap = pcap_open_live(if_name, mtu + sizeof(struct ethernet_hdr), 
            0, 0, pcap_errbuf);
    if (pcap_errbuf[0] != '\0') {
        tc_log_info(LOG_ERR, errno, "pcap open %s, failed:%s", 
                if_name, pcap_errbuf);
        return TC_ERR;
    }

    return TC_OK;
}


int
tc_pcap_snd(unsigned char *frame, size_t len)
{
    int   send_len;
    char  pcap_errbuf[PCAP_ERRBUF_SIZE];

    pcap_errbuf[0]='\0';

    send_len = pcap_inject(pcap, frame, len);
    if (send_len == -1) {
        return TC_ERR;
    }

    return TC_OK;
}


int tc_pcap_over(void)
{
    if (pcap != NULL) {
        pcap_close(pcap);
        pcap = NULL;
    }
     
    return TC_OK;
}



int
tc_socket_set_nonblocking(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return TC_ERR;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return TC_ERR;
    }

    return TC_OK;
}

