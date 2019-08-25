#pragma once

#include <fstream>
#include <string>
#include <regex>
#include <sstream>
#include <vector>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "netfiltermanager.h"

class HarmfulSiteBlocker
{
public:
    HarmfulSiteBlocker();
    HarmfulSiteBlocker(std::string file_name_in);

    static void SetOnEventOccured(std::function<void(std::string)> on_event_occured_in);
    void Start(uint16_t queue_number);
    void Stop();
    int Receive();
    void Handle();

private:
    NetfilterManager netfilter_manager;
    static std::vector<std::string> harmful_sites;

    static std::function<void(std::string)> on_event_occured;

    static void ReadHarmfulSitesFromFile(std::string file_name_in);

    static int InspectPacket(nfq_q_handle *queue_handle, nfgenmsg *message, nfq_data *netfilter_data, void *data);
    static bool IsInHarmfulList(std::string url_in);
};
