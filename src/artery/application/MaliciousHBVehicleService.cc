#include "MaliciousHBVehicleService.h"

#include "HBMessage_m.h"
#include "PseudonymMessage_m.h"
#include "V2VMessage_m.h"
#include "artery/traci/VehicleController.h"

Define_Module(artery::MaliciousHBVehicleService);

namespace artery
{

// mIsAttacker is decided exactly once here, from the attackerShare NED parameter, using this
// module's own local rng-0 (mirrors traci::BasicModuleMapper::equipVehicle()'s explicit
// getRNG(0) pattern). It is never re-rolled anywhere else. With num-rngs=2 and
// **.MaliciousHBVehicleService.rng-0=1 configured in the scenario ini, this draw is isolated
// onto global RNG stream 1, leaving stream 0 (mobility/module-mapper/service drop-delay
// draws) untouched -- required for the attackerShare=0 regression check to reproduce the
// existing baseline's stream-0 draw sequence unperturbed.
//
// ATTACKER_TAGGED is ground-truth logging: verify_baseline.py's effective-revocation-time
// calculation (eff = trev hashes matched with SELF_REVOKE_PRL) silently drops any revoked
// hash that never produces a matching SELF_REVOKE_PRL, with no exclusion counter at all. An
// attacker vehicle that gets legitimately revoked will never produce SELF_REVOKE_PRL (it
// never processes HB content) -- this line lets the analysis script identify that case
// instead of it vanishing from the metric unexplained.
void MaliciousHBVehicleService::initialize()
{
    VehicleHBService::initialize();

    omnetpp::cRNG* rng = getRNG(0);
    double dice = omnetpp::uniform(rng, 0.0, 1.0);
    mIsAttacker = dice < par("attackerShare").doubleValue();

    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    Logger::log("ATTACKER_TAGGED," + std::to_string(omnetpp::simTime().dbl()) +
        "," + vehicle.getVehicleId() + "," + (mIsAttacker ? "1" : "0"));
}

// At attackerShare=0 (mIsAttacker always false), this delegates the entire call to
// VehicleHBService::indicate() unchanged -- provably identical behavior to the unmodified
// base service, not a re-implementation that could drift out of sync with it. Only when
// mIsAttacker is true does this override take over, dropping HBMessage packets (not calling
// handleHBMessage(), so this vehicle never learns it should self-revoke) while replicating
// every other branch of VehicleHBService::indicate() (VehicleHBService.cc) exactly, including
// the unconditional mState==REVOKED early exit and checkDesynchronization() call.
void MaliciousHBVehicleService::indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net)
{
    if (!mIsAttacker) {
        VehicleHBService::indicate(ind, packet, net);
        return;
    }

    Enter_Method("indicate");

    if (mState == VehicleState::REVOKED) {
        delete packet;
        return;
    }

    checkDesynchronization(omnetpp::simTime());

    if (packet) {
        if (dynamic_cast<HBMessage*>(packet)) {
            // Gray-hole: drop the heartbeat/PRL update, do not call handleHBMessage().
        } else if (auto* pseudonymMessage = dynamic_cast<PseudonymMessage*>(packet)) {
            handlePseudonymMessage(pseudonymMessage);
        } else if (auto* v2vMessage = dynamic_cast<V2VMessage*>(packet)) {
            handleV2VMessage(v2vMessage);
        }
    }
    delete packet;
}

}  // namespace artery
