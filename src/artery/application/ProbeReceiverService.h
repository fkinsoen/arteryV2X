#ifndef ARTERY_PROBERECEIVERSERVICE_H_
#define ARTERY_PROBERECEIVERSERVICE_H_

#include "artery/application/ItsG5Service.h"

namespace artery
{

// THROWAWAY, spike-only: minimal CRL-reception counter for the distance-probe PHY-jamming
// investigation. Does NOT verify signatures or merge CRL content -- the only thing being
// measured is whether a CRLMessage broadcast reaches indicate() at all (i.e. survived MAC/PHY
// reception), which is exactly what a distance-vs-reception-rate curve needs. Runs on a
// stationary RSU-type node (no traci::VehicleController dependency), identified purely by its
// own module name (set via ini per probe index) so no TraCI/mobility coupling is needed.
class ProbeReceiverService : public ItsG5Service
{
protected:
    void initialize() override;
    void indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net) override;

private:
    std::string mProbeId;
};

} // namespace artery

#endif /* ARTERY_PROBERECEIVERSERVICE_H_ */
