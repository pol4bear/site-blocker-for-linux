#include "netfiltermanager.h"

using namespace std;

NetfilterManager::NetfilterManager()
{

}

void NetfilterManager::Start(uint16_t queue_number, nfq_callback *callback)
{
    handle = nfq_open();
    if(!handle)
        throw new runtime_error("Cannot open nfq handle");

    if (nfq_unbind_pf(handle, AF_INET) < 0)
        throw new runtime_error("Cannot unbind existing nfq handle");

    if(nfq_bind_pf(handle, AF_INET) < 0)
        throw new runtime_error("Cannot bind existing nfq handle");

    if(callback == nullptr) {
        queue_handle = nfq_create_queue(handle, queue_number, &DefaultCallback, nullptr);
    }
    else{
        queue_handle = nfq_create_queue(handle, queue_number, callback, nullptr);
    }
    if (!queue_handle)
        throw new runtime_error("Cannot create netfilter queue");

    if (nfq_set_mode(queue_handle, NFQNL_COPY_PACKET, 0xffff) < 0)
        throw new runtime_error("Cannot change mode to copy");

    fd = nfq_fd(handle);

    is_started = true;
}

void NetfilterManager::Stop()
{
    if(!is_started) return;

    nfq_destroy_queue(queue_handle);
    nfq_close(handle);
}

int NetfilterManager::Receive()
{
    received = recv(fd, buf, sizeof(buf), 0);

    return received;
}

void NetfilterManager::Handle() {
    if (received < 1) return;

    nfq_handle_packet(handle, buf, received);
}

int NetfilterManager::DefaultCallback(nfq_q_handle *queue_handle, nfgenmsg *message, nfq_data *netfilter_data, void *data)
{
    nfqnl_msg_packet_hdr *packet_header;

    packet_header = nfq_get_msg_packet_hdr(netfilter_data);

    if (!packet_header) return nfq_set_verdict(queue_handle, 0, NF_ACCEPT, 0, NULL);

    int id = ntohl(packet_header->packet_id);

    return nfq_set_verdict(queue_handle, id, NF_ACCEPT, 0, NULL);
}
