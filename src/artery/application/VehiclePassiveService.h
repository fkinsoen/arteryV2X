#ifndef VEHICLE_CRLSERVICE_H
#define VEHICLE_CRLSERVICE_H

#include "Logger.h"
#include "CRLMessageHandler.h"
#include "CRLMessage_m.h"
#include "ItsG5Service.h"
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

class VehiclePassiveService : public ItsG5Service
{
public:
    enum class VehicleState {
        NOT_ENROLLED,
        ENROLLMENT_REQUESTED,
        ENROLLED
    };

protected:
    void initialize() override;
    void indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net) override;
    void trigger() override;
    void handleMessage(omnetpp::cMessage* msg) override;

private:
    void handlePseudonymMessage(PseudonymMessage* pseudonymMessage);
    void handleV2VMessage(V2VMessage* v2vMessage);
    bool isRevoked(const vanetza::security::Certificate& certificate) const;
    bool checkEnrolled();
    void sendEnrollmentRequest();
    void sendV2VMessage();
    std::string hashedId8ToHexString(const vanetza::security::HashedId8& hashedId);

    // Mobile jamming bubble: single guard evaluated once per received packet, before the
    // dynamic_cast dispatch chain (see JammingCheck.h for the actual radius test). Passive
    // has no peer-to-peer revocation broadcast, so the scheme's own "revocation-carrying"
    // message is the RA's pseudonym-renewal response (PseudonymMessage) -- jamming it delays
    // the RECEIVING vehicle's own re-authorization, a different causal mechanism from
    // active/self (where jamming suppresses a THIRD vehicle's revocation news). Called with
    // logTag="JAM_CHECK" for PseudonymMessage/anything else this service receives
    // (indiscriminate drop), and separately with logTag="JAM_CHECK_V2V_CENSORED" for
    // V2VMessage, the peer-to-peer ground-truth traffic the effective-revocation-time
    // metric (RECV) is measured against -- kept distinguishable from the RA-side
    // REVOKE/DENIAL metric, which this guard does not affect either way.
    bool checkJammingBubble(const std::string& messageType, const std::string& logTag);

    std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    vanetza::security::Certificate mPseudonymCertificate;
    vanetza::security::Time32 mPseudonymTime;
    omnetpp::simtime_t mRequestTime;
    std::unique_ptr<V2VMessageHandler> mV2VHandler;
    std::unique_ptr<PseudonymMessageHandler> mPseudonymHandler;

    bool mJammingEnabled = false;
    vanetza::units::Length mJammingRadius;
    std::string mJammingTimingMode;
    double mJammingT1 = 0.0;
    double mJammingT2 = 0.0;
    GlobalEnvironmentModel* mGlobalEnvironmentModel = nullptr;
    JammerRegistry* mJammerRegistry = nullptr;

    VehicleState mState = VehicleState::NOT_ENROLLED;

    static const vanetza::ItsAid ENROLLMENT_ITS_AID;
    static const vanetza::ItsAid V2V_ITS_AID;
};

}  // namespace artery

#endif  // VEHICLE_PASSIVESERVICE_H
