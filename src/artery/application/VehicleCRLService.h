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

class VehicleCRLService : public ItsG5Service
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

    // Exposed (private -> protected) for MaliciousCRLVehicleService (A1 gray-hole attack):
    // its indicate() override must delegate to handlePseudonymMessage()/handleV2VMessage()
    // and replicate the inline mState check indicate() performs on the PseudonymMessage branch.
    void handleCRLMessage(CRLMessage* crlMessage);
    void handlePseudonymMessage(PseudonymMessage* pseudonymMessage);
    void handleV2VMessage(V2VMessage* v2vMessage);
    VehicleState mState = VehicleState::NOT_ENROLLED;
    std::vector<vanetza::security::HashedId8> mLocalCRL;

private:
    void updateLocalCRL(const std::vector<vanetza::security::HashedId8>& revokedCertificates);
    bool isRevoked(const vanetza::security::HashedId8& certificateHash) const;
    void sendEnrollmentRequest();
    void sendV2VMessage();
    std::string convertToHexString(const vanetza::security::HashedId8& hashedId);

    // Mobile jamming bubble: single guard evaluated once per received packet, before the
    // dynamic_cast dispatch chain (see JammingCheck.h for the actual radius test). Returns
    // true (and logs the decision under `logTag`, tagged with `messageType` for
    // post-processing) if this packet must be dropped because a currently-active jammer
    // vehicle is within jammingRadius of this vehicle's own position during the configured
    // time window. Called with logTag="JAM_CHECK" for CRLMessage/PseudonymMessage/anything
    // else this service receives (indiscriminate drop), and separately with
    // logTag="JAM_CHECK_V2V_CENSORED" for V2VMessage, since that is the peer-to-peer
    // ground-truth traffic the effective-revocation-time metric is measured against and
    // must remain distinguishable from a scheme-level accept/reject decision.
    bool checkJammingBubble(const std::string& messageType, const std::string& logTag);

    std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    vanetza::security::Certificate mPseudonymCertificate;
    std::unique_ptr<CRLMessageHandler> mCRLHandler;
    std::unique_ptr<V2VMessageHandler> mV2VHandler;
    std::unique_ptr<PseudonymMessageHandler> mPseudonymHandler;

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

#endif  // VEHICLE_CRLSERVICE_H
