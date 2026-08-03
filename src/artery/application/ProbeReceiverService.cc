#include "artery/application/ProbeReceiverService.h"
#include "CRLMessage_m.h"
#include "Logger.h"

#include <omnetpp.h>

Define_Module(artery::ProbeReceiverService)

namespace artery
{

void ProbeReceiverService::initialize()
{
    ItsG5Service::initialize();
    mProbeId = findHost()->getFullName(); // e.g. "rsu[2]" -- set via ini per probe index
}

void ProbeReceiverService::indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net)
{
    Enter_Method("indicate");

    if (dynamic_cast<CRLMessage*>(packet)) {
        Logger::log("PROBE_CRL_RECEIVED," + std::to_string(omnetpp::simTime().dbl()) + "," + mProbeId);
    }

    delete packet;
}

} // namespace artery
