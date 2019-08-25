#include "harmfulsiteblocker.h"

using namespace std;

function<void(std::string)> HarmfulSiteBlocker::on_event_occured;
vector<string> HarmfulSiteBlocker::harmful_sites;

HarmfulSiteBlocker::HarmfulSiteBlocker()
{

}

HarmfulSiteBlocker::HarmfulSiteBlocker(string file_name_in)
{
    if(file_name_in == "") return;

    try {
        ReadHarmfulSitesFromFile(file_name_in);
    }
    catch(exception e){
        throw e;
    }
}

void HarmfulSiteBlocker::SetOnEventOccured(std::function<void (string)> on_event_occured_in)
{
    on_event_occured = on_event_occured_in;
}

void HarmfulSiteBlocker::Start(uint16_t queue_number){
    try{
        netfilter_manager.Start(queue_number, &InspectPacket);
    }
    catch(runtime_error e){
        throw e;
    }
}

void HarmfulSiteBlocker::Stop()
{
    netfilter_manager.Stop();
}

int HarmfulSiteBlocker::Receive()
{
    return netfilter_manager.Receive();
}


void HarmfulSiteBlocker::Handle()
{
    netfilter_manager.Handle();
}

void HarmfulSiteBlocker::ReadHarmfulSitesFromFile(string file_name_in)
{
    if(file_name_in == "") return;

    ifstream input_file(file_name_in);

    if(!input_file.is_open()) throw invalid_argument("Cannot open file " + file_name_in);

    string line;
    while(input_file.peek() != EOF){
        getline(input_file, line);

        if(line == "") continue;

        harmful_sites.push_back(line);
    }
}

int HarmfulSiteBlocker::InspectPacket(nfq_q_handle *queue_handle_in, nfgenmsg *message_in, nfq_data *netfilter_data_in, void *data_in)
{
    uint32_t id = 0;
    nfqnl_msg_packet_hdr *packet_header;
    uint8_t *packet_data;
    int data_length;

    packet_header = nfq_get_msg_packet_hdr(netfilter_data_in);
    if(!packet_header)
        return nfq_set_verdict(queue_handle_in, id, NF_ACCEPT, 0, nullptr);

    id = ntohl(packet_header->packet_id);
    uint16_t protocol = ntohs(packet_header->hw_protocol);
    if(protocol != ETHERTYPE_IP)
        return nfq_set_verdict(queue_handle_in, id, NF_ACCEPT, 0, nullptr);

    data_length = nfq_get_payload(netfilter_data_in, &packet_data);
    if(data_length < 1)
        return nfq_set_verdict(queue_handle_in, id, NF_ACCEPT, 0, nullptr);

    iphdr *ip_header = reinterpret_cast<iphdr*>(packet_data);
    int ip_header_length = ip_header->ihl * 4;

    if(ip_header->protocol != IPPROTO_TCP)
        return nfq_set_verdict(queue_handle_in, id, NF_ACCEPT, 0, nullptr);

    tcphdr *tcp_header = reinterpret_cast<tcphdr*>(packet_data + ip_header_length);
    int tcp_header_length = tcp_header->doff * 4;

    int payload_length = ntohs(ip_header->tot_len) - ip_header_length - tcp_header_length;

    if(payload_length < 1)
        return nfq_set_verdict(queue_handle_in, id, NF_ACCEPT, 0, nullptr);

    string str_data((char*)packet_data + ip_header_length + tcp_header_length, payload_length);
    stringstream stream_data;
    stream_data.str(str_data);

    string line;
    getline(stream_data, line);
    string resource;
    {
        regex http_request("^ *(GET|POST) *((\\/[\\d\\w-_]*)(\\/[\\d\\w-_]+)*) *HTTP\\/1\\.[0-1] *\\r?$");
        smatch matches;
        if(!regex_search(line, matches, http_request))
            return nfq_set_verdict(queue_handle_in, id, NF_ACCEPT, 0, nullptr);

        resource = matches[2].str();
    }

    getline(stream_data, line);
    string host;
    {
        regex http_host("^ *Host: *([\\d\\w.]+) *\\r?$");
        smatch matches;
        if(!regex_search(line, matches, http_host))
            return nfq_set_verdict(queue_handle_in, id, NF_ACCEPT, 0, nullptr);

        host = matches[1].str();
    }


    if(IsInHarmfulList(host)){
        string msg = "Connection to " + host + resource + " blocked";
        if(on_event_occured != nullptr)
            on_event_occured(msg);

        return nfq_set_verdict(queue_handle_in, id, NF_DROP, 0, nullptr);
    }


    return nfq_set_verdict(queue_handle_in, id, NF_ACCEPT, 0, nullptr);
}

bool HarmfulSiteBlocker::IsInHarmfulList(string url_in)
{
    for(vector<string>::iterator url = harmful_sites.begin(); url != harmful_sites.end(); url++) {
        if(url_in == *url)
            return true;
    }

    return false;
}
