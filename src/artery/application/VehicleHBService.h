#ifndef VEHICLE_HBSERVICE_H
#define VEHICLE_HBSERVICE_H

#include "HBMessageHandler.h"
#include "HBMessage_m.h"
#include "ItsG5Service.h"
#include "Logger.h"
#include "PseudonymMessageHandler.h"
#include "PseudonymMessage_m.h"
#include "V2VMessageHandler.h"
#include "vanetza/security/backend.hpp"
#include "vanetza/security/ecdsa256.hpp"
#include <vanetza/units/length.hpp>

#include <omnetpp.h>

#include <memory>

namespace artery
{

class GlobalEnvironmentModel;
class JammerRegistry;

class VehicleHBService : public ItsG5Service
{
public:
    enum class VehicleState { NOT_ENROLLED, ENROLLMENT_REQUESTED, ENROLLED, REVOKED };

protected:
    void initialize() override;
    void indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net) override;
    void trigger() override;

    // Exposed (private -> protected) for MaliciousHBVehicleService (A1 gray-hole attack):
    // its indicate() override must delegate to handlePseudonymMessage()/handleV2VMessage(),
    // replicate the inline mState==REVOKED check, and still call checkDesynchronization()
    // (called unconditionally by indicate() for every indication, not just HB messages).
    void handlePseudonymMessage(PseudonymMessage* pseudonymMessage);
    void handleHBMessage(HBMessage* heartbeatMessage);
    void handleV2VMessage(V2VMessage* v2vMessage);
    void checkDesynchronization(omnetpp::simtime_t messageTimestamp);
    VehicleState mState;
    double mInternalClock;
    double mTv;

private:
    void performSelfRevocation();
    std::string hashedId8ToHexString(const vanetza::security::HashedId8& hashedId);

    // Mobile jamming bubble: single guard evaluated once per received packet, before the
    // dynamic_cast dispatch chain (see JammingCheck.h for the actual radius test). Called
    // with logTag="JAM_CHECK" for HBMessage/PseudonymMessage/anything else this service
    // receives (indiscriminate drop), and separately with logTag="JAM_CHECK_V2V_CENSORED"
    // for V2VMessage, since that is the peer-to-peer ground-truth traffic the
    // effective-revocation-time metric is measured against and must remain distinguishable
    // from a scheme-level accept/reject decision.
    bool checkJammingBubble(const std::string& messageType, const std::string& logTag);

    std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    vanetza::security::Certificate mPseudonymCertificate;
    std::unique_ptr<V2VMessageHandler> mV2VHandler;
    std::unique_ptr<PseudonymMessageHandler> mPseudonymHandler;
    std::unique_ptr<HBMessageHandler> mHBHandler;

    bool mJammingEnabled = false;
    vanetza::units::Length mJammingRadius;
    std::string mJammingTimingMode;
    double mJammingT1 = 0.0;
    double mJammingT2 = 0.0;
    GlobalEnvironmentModel* mGlobalEnvironmentModel = nullptr;
    JammerRegistry* mJammerRegistry = nullptr;

    static const vanetza::ItsAid ENROLLMENT_ITS_AID;
    static const vanetza::ItsAid V2V_ITS_AID;
};

}  // namespace artery

#endif  // VEHICLE_HBSERVICE_H