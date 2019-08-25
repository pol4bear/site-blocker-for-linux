#pragma once

#include <stdexcept>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <unistd.h>
#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>

class NetfilterManager
{
public:
    NetfilterManager();

    void Start(uint16_t queue_number, nfq_callback *callback = nullptr);
    void Stop();
    int Receive();
    void Handle();

    uint32_t PrintPacket(nfq_data *tb);

private:
     bool is_started;
     nfq_handle *handle;
     nfq_q_handle *queue_handle;
     int fd;
     int received;
     char buf[4096] __attribute__ ((aligned));

     static int DefaultCallback(nfq_q_handle *queue_handle, nfgenmsg *message, nfq_data *netfilter_data, void *data);
};
