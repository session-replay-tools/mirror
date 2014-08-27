
#include <xcopy.h>
#include <mirror.h>


static  pcap_t  *pcap_map[MAX_FD_NUM];
static int proc_pcap_pack(tc_event_t *);
static int special_disp_packet(unsigned char *, int);


static int 
device_set(tc_event_loop_t *event_loop, device_t *device) 
{
    int         fd;
    tc_event_t *ev;

    fd = tc_pcap_socket_in_init(&(device->pcap), device->name,
            PCAP_RCV_BUF_SIZE, clt_settings.buffer_size, clt_settings.filter);
    if (fd == TC_INVALID_SOCK) {
        return TC_ERR;
    }

    pcap_map[fd] = device->pcap;

    ev = tc_event_create(event_loop->pool, fd, proc_pcap_pack, NULL);
    if (ev == NULL) {
        return TC_ERR;
    }

    if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "add socket(%d) to event loop failed.", fd);
        return TC_ERR;
    }

    return TC_OK;
}


int
tc_packets_init(tc_event_loop_t *event_loop)
{
    int                  i;
    bool                 work;
    char                 ebuf[PCAP_ERRBUF_SIZE];
    devices_t           *devices;
    pcap_if_t           *alldevs, *d;
    struct ethernet_hdr *ether;

    tc_pcap_snd_init(clt_settings.output_if_name, clt_settings.mtu);

    devices = &(clt_settings.devices);
    if (clt_settings.raw_device == NULL) {
        if (pcap_findalldevs(&alldevs, ebuf) == -1) {
            tc_log_info(LOG_ERR, 0, "error in pcap_findalldevs:%s", ebuf);
            return TC_ERR;
        }
        
        i = 0;
        for (d = alldevs; d; d = d->next)
        {
            if (strcmp(d->name, DEFAULT_DEVICE) == 0) {
                continue;
            }

            if (i >= MAX_DEVICE_NUM) {
                pcap_freealldevs(alldevs);
                tc_log_info(LOG_ERR, 0, "too many devices");
                return TC_ERR;
            }

            strcpy(devices->device[i++].name, d->name);
        }
        devices->device_num = i;
        pcap_freealldevs(alldevs);
    }

    work = false;
    for (i = 0; i < devices->device_num; i++) {
        if (device_set(event_loop, &(devices->device[i]))
                == TC_ERR) 
        {
            tc_log_info(LOG_WARN, 0, "device could not work:%s", 
                    devices->device[i].name);
        } else {
            work = true;
        }
    }

    if (!work) {
        tc_log_info(LOG_ERR, 0, "no device available for snooping packets");
        return TC_ERR;
    }

    ether = (struct ethernet_hdr *) clt_settings.pack_buffer;
    fill_frame(ether, clt_settings.smac, clt_settings.dmac);

    return TC_OK;
}


static void
pcap_retrieve(unsigned char *args, const struct pcap_pkthdr *pkt_hdr,
        unsigned char *frame)
{
    int                  l2_len, ip_pack_len, frame_len, ret;
    pcap_t              *pcap;
    tc_iph_t            *ip;
    unsigned char       *ip_data; 
    struct ethernet_hdr *ether;

    if (pkt_hdr->len < ETHERNET_HDR_LEN) {
        tc_log_info(LOG_ERR, 0, "recv len is less than:%d", ETHERNET_HDR_LEN);
        return;
    }

    ip_data = NULL;
    pcap = (pcap_t *) args;
    
    frame_len = pkt_hdr->len;
    l2_len    = get_l2_len(frame, pcap_datalink(pcap));

    if (l2_len != ETHERNET_HDR_LEN) {
        if ((size_t) l2_len > ETHERNET_HDR_LEN) {
            ip_data = get_ip_data(pcap, frame, pkt_hdr->len, &l2_len); 
        } else if (l2_len == 0) {
            ip_pack_len = 
            /* tunnel frames without ethernet header */
            special_disp_packet(ip_data, pkt_hdr->len);
            return;
        } else {
            tc_log_info(LOG_WARN, 0, "l2 len is %d", l2_len);
            return;
        }
    } else {
        ether = (struct ethernet_hdr *) frame;
        if (ntohs(ether->ether_type) != ETH_P_IP) {
            return;
        }
        ip_data = get_ip_data(pcap, frame, pkt_hdr->len, &l2_len); 
    }

    ip_pack_len = pkt_hdr->len - l2_len;

    if (ip_pack_len <= clt_settings.mtu) {
        fill_frame(ether, clt_settings.smac, clt_settings.dmac);
        ip = (tc_iph_t *) ip_data;
        ip->daddr = clt_settings.target_ip;
        ret = tc_pcap_snd(frame, ip_pack_len + ETHERNET_HDR_LEN);
        if (ret == TC_ERR) {
            tc_log_info(LOG_WARN, 0, "pcap send error");
        }
    } else {
        special_disp_packet(ip_data, ip_pack_len);
    }
}


static int
proc_pcap_pack(tc_event_t *rev)
{
    pcap_t *pcap;

    pcap = pcap_map[rev->fd];
    pcap_dispatch(pcap, 10, (pcap_handler) pcap_retrieve, (u_char *) pcap);

    return TC_OK;
}



static int
special_disp_packet(unsigned char *packet, int ip_rcv_len)
{
    int        i, last, packet_num, max_payload,
               index, payload_len, ret;
    char      *p;
    uint16_t   id, size_ip, size_tcp, tot_len, cont_len, 
               pack_len, head_len;
    uint32_t   seq;
    tc_iph_t  *ip;
    tc_tcph_t *tcp;

    ip   = (tc_iph_t *) packet;

    size_ip     = ip->ihl << 2;
    tcp  = (tc_tcph_t *) ((char *) ip + size_ip);

    tot_len     = ntohs(ip -> tot_len);
    if (tot_len != ip_rcv_len) {
        tc_log_info(LOG_WARN, 0, "packet len:%u, recv len:%u",
                tot_len, ip_rcv_len);
        return TC_ERR;
    }

    size_tcp    = tcp->doff << 2;
    cont_len    = tot_len - size_tcp - size_ip;
    head_len    = size_ip + size_tcp;
    max_payload = clt_settings.mtu - head_len;
    packet_num  = (cont_len + max_payload - 1)/max_payload;
    seq         = ntohl(tcp->seq);
    last        = packet_num - 1;
    id          = ip->id;

    index = head_len;

    pack_len = 0;
    for (i = 0 ; i < packet_num; i++) {
        tcp->seq = htonl(seq + i * max_payload);
        if (i != last) {
            pack_len  = clt_settings.mtu;
        } else {
            pack_len += (cont_len - packet_num * max_payload);
        }
        payload_len = pack_len - head_len;
        ip->tot_len = htons(pack_len);
        ip->id = id++;
        p = (char *) (clt_settings.pack_buffer + ETHERNET_HDR_LEN);
        /* copy header here */
        memcpy(p, (char *) packet, head_len);
        p +=  head_len;
        /* copy payload here */
        memcpy(p, (char *) (packet + index), payload_len);
        index = index + payload_len;
        
        ip->daddr = clt_settings.target_ip;

        ret = tc_pcap_snd(clt_settings.pack_buffer, 
                pack_len + ETHERNET_HDR_LEN);
        if (ret == TC_ERR) {
            tc_log_info(LOG_WARN, 0, "pcap send error");
        }
    }

    return TC_OK;
}

