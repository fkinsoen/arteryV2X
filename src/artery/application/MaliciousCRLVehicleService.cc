#include "MaliciousCRLVehicleService.h"

#include "CRLMessage_m.h"
#include "PseudonymMessage_m.h"
#include "V2VMessage_m.h"
#include "artery/traci/VehicleController.h"

#include <iostream>

Define_Module(artery::MaliciousCRLVehicleService);

namespace artery
{

// mIsAttacker is decided exactly once here, from the attackerShare NED parameter, using this
// module's own local rng-0 (mirrors traci::BasicModuleMapper::equipVehicle()'s explicit
// getRNG(0) pattern). It is never re-rolled anywhere else. With num-rngs=2 and
// **.MaliciousCRLVehicleService.rng-0=1 configured in the scenario ini, this draw is isolated
// onto global RNG stream 1, leaving stream 0 (mobility/module-mapper/service drop-delay
// draws) untouched -- required for the attackerShare=0 regression check to reproduce the
// existing baseline's stream-0 draw sequence unperturbed.
//
// ATTACKER_TAGGED is ground-truth logging: verify_baseline.py's excluded_never_received
// bucket (a receiver with no CRL_RECEIVED event) cannot otherwise distinguish a benign
// vehicle that just hasn't gotten its first CRL yet from an attacker vehicle that will
// NEVER get one, by construction, for its entire lifetime. This line lets the analysis
// script tell the two apart.
void MaliciousCRLVehicleService::initialize()
{
    VehicleCRLService::initialize();

    omnetpp::cRNG* rng = getRNG(0);
    double dice = omnetpp::uniform(rng, 0.0, 1.0);
    mIsAttacker = dice < par("attackerShare").doubleValue();

    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    Logger::log("ATTACKER_TAGGED," + std::to_string(omnetpp::simTime().dbl()) +
        "," + vehicle.getVehicleId() + "," + (mIsAttacker ? "1" : "0"));
}

// At attackerShare=0 (mIsAttacker always false), this delegates the entire call to
// VehicleCRLService::indicate() unchanged -- provably identical behavior to the unmodified
// base service, not a re-implementation that could drift out of sync with it. Only when
// mIsAttacker is true does this override take over, dropping CRLMessage packets (not calling
// handleCRLMessage(), so mLocalCRL is never updated) while replicating every other branch of
// VehicleCRLService::indicate() (VehicleCRLService.cc) exactly.
void MaliciousCRLVehicleService::indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net)
{
    if (!mIsAttacker) {
        VehicleCRLService::indicate(ind, packet, net);
        return;
    }

    Enter_Method("indicate");

    if (!packet) {
        std::cout << "Received packet is nullptr. Ignoring." << std::endl;
        return;
    }

    if (dynamic_cast<CRLMessage*>(packet)) {
        // Gray-hole: drop the CRL update, do not call handleCRLMessage().
    } else if (auto* pseudonymMessage = dynamic_cast<PseudonymMessage*>(packet)) {
        if (mState == VehicleState::ENROLLED) {
            delete pseudonymMessage;
            return;
        }
        handlePseudonymMessage(pseudonymMessage);
    } else if (auto* v2vMessage = dynamic_cast<V2VMessage*>(packet)) {
        handleV2VMessage(v2vMessage);
    }

    delete packet;
}

}  // namespace artery
