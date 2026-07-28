#ifndef MALICIOUS_HB_VEHICLE_SERVICE_H
#define MALICIOUS_HB_VEHICLE_SERVICE_H

#include "VehicleHBService.h"

namespace artery
{

// A1 (selective forwarding / gray-hole, self-revocation): drops incoming heartbeat/PRL
// updates entirely while otherwise behaving exactly like VehicleHBService.
class MaliciousHBVehicleService : public VehicleHBService
{
protected:
    void initialize() override;
    void indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net) override;

private:
    // Decided once in initialize() from the attackerShare NED parameter, never re-rolled.
    bool mIsAttacker = false;
};

}  // namespace artery

#endif  // MALICIOUS_HB_VEHICLE_SERVICE_H
