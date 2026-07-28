#ifndef MALICIOUS_CRL_VEHICLE_SERVICE_H
#define MALICIOUS_CRL_VEHICLE_SERVICE_H

#include "VehicleCRLService.h"

namespace artery
{

// A1 (selective forwarding / gray-hole, active revocation): drops incoming CRL updates
// entirely while otherwise behaving exactly like VehicleCRLService.
class MaliciousCRLVehicleService : public VehicleCRLService
{
protected:
    void initialize() override;
    void indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net) override;

private:
    // Decided once in initialize() from the attackerShare NED parameter, never re-rolled.
    bool mIsAttacker = false;
};

}  // namespace artery

#endif  // MALICIOUS_CRL_VEHICLE_SERVICE_H
