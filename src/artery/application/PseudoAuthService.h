#ifndef PSEUDO_AUTH_SERVICE_H
#define PSEUDO_AUTH_SERVICE_H

#include "CRLMessage_m.h"
#include "CentralAuthService.h"
#include "PassiveRevocationMetrics.cc"

#include <vector>

namespace artery
{

class PseudoAuthService : public CentralAuthService
{
public:
    void initialize() override;
    void finish() override;
    void handleMessage(omnetpp::cMessage* msg) override;

protected:
    void handleEnrollmentRequest(EnrollmentRequest* request) override;
    void revokeRandomCertificate() override;
    void scheduleNextRevocation();
    void scheduleNextBurstRevocation();
    void revokeBurst();
    void sendPseudonym(PseudonymMessage* pseudonymMessage);
    void generateandSendPseudo(vanetza::security::Certificate& pseudoCert, vanetza::security::ecdsa256::PublicKey& publicKey, std::string& vehicleId);
    // Logs which certificate hash a vehicle holds at issuance time, since REVOKE only carries
    // the vehicleId and RECV only carries the sender's certificate hash -- without this, there
    // is no way to join the two and compute a receiver-side effective-revocation-time metric
    // for passive revocation the way active/self-revocation's own logs already allow.
    void recordCertificateIssuance(const std::string& vehicleId, const vanetza::security::Certificate& cert) override;

private:
    std::vector<std::string> mRevocationList;
    omnetpp::simtime_t mRevocationInterval;
    static const double MAX_REVOCATION_RATE;
     std::unique_ptr<PassiveRevocationMetrics> mMetrics;
};

}  // namespace artery

#endif  // PSEUDO_AUTH_SERVICE_H