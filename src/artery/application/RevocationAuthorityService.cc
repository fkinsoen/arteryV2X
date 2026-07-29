#include "RevocationAuthorityService.h"

#include "CRLMessage_m.h"
#include "EnrollmentRequest_m.h"
#include "PseudonymMessage_m.h"
#include "artery/networking/GeoNetPacket.h"
#include "artery/networking/Router.h"
#include "certify/generate-certificate.hpp"
#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"

#include <arpa/inet.h>
#include <inet/common/ModuleAccess.h>
#include <omnetpp.h>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/btp/header.hpp>
#include <vanetza/btp/ports.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/subject_info.hpp>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

Define_Module(artery::RevocationAuthorityService)

using namespace artery;
using namespace vanetza;
using namespace security;
using namespace omnetpp;

const double RevocationAuthorityService::MAX_REVOCATION_RATE = 0.30;
const vanetza::ItsAid RevocationAuthorityService::CRL_ITS_AID = 622;

void RevocationAuthorityService::initialize()
{
    CentralAuthService::initialize();

    auto now = std::chrono::system_clock::now();
    auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
    auto value = now_ms.time_since_epoch();
    long seed = value.count();

    std::cout << "Using seed based on system time: " << seed << endl;

    // Get the configuration
    cConfiguration* config = getEnvir()->getConfig();

    // Initialize the RNG
    getRNG(0)->initialize(seed, 0, 1, 0, 1, config);

    Logger::init("active_revocations.txt");
    Logger::log("Simulation started, logger initialized");

    mMetrics = std::unique_ptr<ActiveRevocationMetrics>(new ActiveRevocationMetrics());
    mCrlGenInterval = par("crlGenInterval").doubleValue();
    mMinRevocationInterval = par("minRevocationInterval").doubleValue();
    mMaxRevocationInterval = par("maxRevocationInterval").doubleValue();

    mDropProbability = par("dropProbability").doubleValue();
    mDelayProbability = par("delayProbability").doubleValue();
    mDelayMean = par("delayMean").doubleValue();
    mDelayStdDev = par("delayStdDev").doubleValue();

    mMaxCrlEntries = static_cast<size_t>(par("maxCrlEntries").intValue());

    // Consistency check between this module's entry cap and the GN SDU ceiling it must fit
    // under -- reads the Router's ACTUAL maxSduSize parameter live (same routerModule +
    // getModuleFromPar<Router> pattern LocationTableLogger already uses to reach the same
    // module), not a hand-duplicated shadow value that could drift out of sync with it (the
    // way MAX_ENTRIES=112 itself had already drifted between this file and
    // SelfRevocationAuthService.cc before this fix). Same 496 + 8*N formula sendCRL() itself
    // uses for messageSize, PLUS the BTP header (vanetza::btp::HeaderB::length_bytes, 4
    // bytes) that artery::Router::request() attaches to the packet before validate_payload()
    // runs -- confirmed by an actual crash during smoke-testing this check: at
    // maxCrlEntries=200/maxSduSize=2096 (496+200*8=2096, believed exactly-fitting), sendCRL()
    // still threw cRuntimeError, because the real checked size was 2096+4=2100. Named
    // constant used rather than a hardcoded 4 so this can't silently drift out of sync with
    // vanetza's own header definition. Warning only, not a hard stop: if these two are ever
    // raised inconsistently, sendCRL() will still throw a real cRuntimeError (via
    // Router::request()) the moment mMasterCRL exceeds the true SDU limit -- this is meant to
    // make that misconfiguration traceable in the log well before that happens, not to
    // prevent it. Must NOT fire at the default (112 entries / 1398 bytes) pairing -- verified
    // the corrected formula still doesn't: 496+112*8+4=1396 <= 1398.
    {
        auto* router = inet::getModuleFromPar<artery::Router>(par("routerModule"), findHost());
        size_t liveMaxSduSize = static_cast<size_t>(router->par("maxSduSize").intValue());
        size_t projectedMaxMessageSize = sizeof(CRLMessage) + mMaxCrlEntries * sizeof(vanetza::security::HashedId8) +
            vanetza::btp::HeaderB::length_bytes;
        if (projectedMaxMessageSize > liveMaxSduSize) {
            Logger::log("WARNING: maxCrlEntries=" + std::to_string(mMaxCrlEntries) +
                " would produce a CRL message of up to " + std::to_string(projectedMaxMessageSize) +
                " bytes, exceeding the Router's live maxSduSize=" + std::to_string(liveMaxSduSize) +
                " -- sendCRL() will crash the simulation (cRuntimeError via Router::request()) "
                "once mMasterCRL reaches this size unless the Router's maxSduSize is raised to "
                "match.");
        }
    }

    std::string mode = par("revocationMode").stdstringValue();
    if (mode == "interval") {
        mRevocationMode = RevocationMode::INTERVAL;
    } else if (mode == "burst") {
        mRevocationMode = RevocationMode::BURST;

        mBurstRevocationTimes = {1000, 2000};
    } else {
        throw cRuntimeError("Invalid revocation mode specified");
    }

    scheduleAt(simTime() + mCrlGenInterval, new cMessage("triggerCRLGen"));

    if (mRevocationMode == RevocationMode::INTERVAL) {
        scheduleNextRevocation();
    } else {
        scheduleNextBurstRevocation();
    }
}

void RevocationAuthorityService::scheduleNextRevocation()
{
    simtime_t nextRevocation = uniform(mMinRevocationInterval, mMaxRevocationInterval);
    scheduleAt(simTime() + nextRevocation, new cMessage("triggerRevocation"));
}

void RevocationAuthorityService::revokeBurst()
{
    int burstSize = 7;

    for (int i = 0; i < burstSize; ++i) {
        if (mIssuedCertificates.empty()) {
            break;
        }
        revokeRandomCertificate();
    }
}

void RevocationAuthorityService::scheduleNextBurstRevocation()
{
    simtime_t nextBurstTime = -1;
    for (const auto& burstTime : mBurstRevocationTimes) {
        if (burstTime > simTime()) {
            nextBurstTime = burstTime;
            break;
        }
    }

    if (nextBurstTime != -1) {
        scheduleAt(nextBurstTime, new cMessage("triggerRevocation"));
    }
}


void RevocationAuthorityService::finish()
{
    CentralAuthService::finish();

    Logger::log("Simulation ended, closing logger");
    Logger::close();

    std::string filename = "active_revocation_crl.csv";
    mMetrics->exportToCSV(filename);
    mMetrics->printMetrics();
}

void RevocationAuthorityService::handleMessage(cMessage* msg)
{
    if (strcmp(msg->getName(), "triggerCRLGen") == 0) {
        generateAndSendCRL();
        scheduleAt(simTime() + mCrlGenInterval, msg);
    } else if (strcmp(msg->getName(), "triggerRevocation") == 0) {
        if (mRevocationMode == RevocationMode::INTERVAL) {
            revokeRandomCertificate();
            scheduleNextRevocation();
        } else {
            revokeBurst();
            scheduleNextBurstRevocation();
        }
        delete msg;
    } else if (auto* enrollmentRequest = dynamic_cast<EnrollmentRequest*>(msg)) {
        handleEnrollmentRequest(enrollmentRequest);
        delete msg;
    } else if (auto* crlMessage = dynamic_cast<CRLMessage*>(msg)) {
        std::cout << "Sending delayed CRL..." << std::endl;
        sendCRL(crlMessage);
    } else {
        ItsG5Service::handleMessage(msg);
    }
}

void RevocationAuthorityService::sendCRL(CRLMessage* crlMessage)
{
    vanetza::btp::DataRequestB req;
    req.destination_port = vanetza::host_cast(getPortNumber());
    req.gn.transport_type = vanetza::geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(vanetza::dcc::Profile::DP3));
    req.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    req.gn.its_aid = CRL_ITS_AID;

    size_t messageSize = sizeof(CRLMessage) + mMasterCRL.size() * sizeof(vanetza::security::HashedId8);
    mMetrics->recordCRLDistribution(messageSize, simTime().dbl());
    mMetrics->recordCRLSize(mMasterCRL.size(), simTime().dbl());

    // Warn as the CRL approaches maxCrlEntries so a future abort is traceable in the log
    // instead of only visible as a build-tool exit code. Threshold scales with maxCrlEntries
    // (5-entry margin, matching the original hardcoded 107-at-112 relationship) rather than
    // staying fixed at 107 now that the cap itself is configurable.
    size_t warnThreshold = (mMaxCrlEntries > 5) ? mMaxCrlEntries - 5 : 0;
    if (mMasterCRL.size() >= warnThreshold) {
        Logger::log("WARNING: CRL size " + std::to_string(mMasterCRL.size()) +
            " approaching maxCrlEntries=" + std::to_string(mMaxCrlEntries) + ", simulation may abort.");
    }

    crlMessage->setByteLength(messageSize);
    request(req, crlMessage);
    std::cout << "CRL message sent. Revoked certificates: " << mMasterCRL.size() << std::endl;
}

void RevocationAuthorityService::generateAndSendCRL()
{
    CRLMessage* crlMessage = createAndPopulateCRL();

    // Simulate network conditions
    double rand = uniform(0, 1);
    if (rand < mDropProbability) {
        delete crlMessage;
        std::cout << "CRL dropped due to simulated network loss" << std::endl;
        return;
    } else if (rand < mDropProbability + mDelayProbability) {
        simtime_t delay = std::abs(normal(mDelayMean, mDelayStdDev));
        scheduleAt(simTime() + delay, crlMessage);
        std::cout << "CRL delayed by " << delay << " seconds" << std::endl;
        return;
    }

    sendCRL(crlMessage);
}

CRLMessage* RevocationAuthorityService::createAndPopulateCRL()
{
    CRLMessage* crlMessage = new CRLMessage("CRL");
    crlMessage->setMTimestamp(omnetpp::simTime());
    crlMessage->setMRevokedCertificatesArraySize(mMasterCRL.size());

    for (size_t i = 0; i < mMasterCRL.size(); ++i) {
        crlMessage->setMRevokedCertificates(i, mMasterCRL[i]);
    }

    crlMessage->setMSignerCertificate(mRootCert);

    if (mBackend) {
        vanetza::ByteBuffer dataToSign;

        uint64_t timestamp = static_cast<uint64_t>(crlMessage->getMTimestamp().dbl() * 1e9);
        dataToSign.insert(dataToSign.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));

        for (size_t i = 0; i < crlMessage->getMRevokedCertificatesArraySize(); ++i) {
            auto& hash = crlMessage->getMRevokedCertificates(i);
            dataToSign.insert(dataToSign.end(), hash.data(), hash.data() + hash.size());
        }

        vanetza::ByteBuffer serializedCert = vanetza::security::convert_for_signing(crlMessage->getMSignerCertificate());
        dataToSign.insert(dataToSign.end(), serializedCert.begin(), serializedCert.end());

        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, dataToSign);
        crlMessage->setMSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return crlMessage;
}

void RevocationAuthorityService::revokeRandomCertificate()
{
    if (mIssuedCertificates.empty()) {
        return;
    }

    // Determine the number of certificates to revoke (1 to 5)
    int numRevocations = intrand(3) + 1;

    // Hard cap on mMasterCRL size, now configurable via maxCrlEntries (default 112, the
    // original hardcoded value -- see RevocationAuthorityService.ned). With the current
    // CRLMessage layout (496 bytes fixed + 8 bytes/entry), 112 is the last size that still
    // fits under vanetza's default GN SDU limit (itsGnMaxSduSize = 1398, see
    // extern/vanetza/vanetza/geonet/mib.cpp); raising maxCrlEntries requires raising the
    // Router's own maxSduSize to match (see the consistency check in initialize()), or
    // validate_payload() rejects the message and the run aborts. This truncates/skips this
    // firing's additions rather than letting mMasterCRL grow past the ceiling; the 45-85s
    // trigger interval and the 1-3 per-firing count distribution themselves are left
    // untouched -- this is not a change to revocation scheme behavior.
    size_t remaining = (mMasterCRL.size() < mMaxCrlEntries) ? mMaxCrlEntries - mMasterCRL.size() : 0;
    size_t toAdd = std::min(static_cast<size_t>(numRevocations), remaining);

    if (toAdd < static_cast<size_t>(numRevocations)) {
        Logger::log("CRL_CAP_TRUNCATED," + std::to_string(simTime().dbl()) +
            ",requested=" + std::to_string(numRevocations) + ",added=" + std::to_string(toAdd));
    }

    for (size_t i = 0; i < toAdd; ++i) {
        if (mIssuedCertificates.empty()) {
            break;
        }

        // Define a range for recent enrollments (e.g., last 25% of certificates)
        size_t recentEnrollmentCount = std::max(size_t(1), mIssuedCertificates.size() / 4);

        // Select a random certificate from the recent enrollments
        auto it = mIssuedCertificates.end();
        std::advance(it, -static_cast<long>(intrand(recentEnrollmentCount) + 1));

        vanetza::security::HashedId8 hashedId = calculate_hash(it->second);

        if (std::find(mMasterCRL.begin(), mMasterCRL.end(), hashedId) == mMasterCRL.end()) {
            mMasterCRL.push_back(hashedId);
        }

        std::string vehicleId = it->first;
        mIssuedCertificates.erase(it);

        std::cout << "Vehicle " << vehicleId << " revoked. CRL size: " << mMasterCRL.size() << std::endl;

        std::string logEntry = "REVOCATION_START," + std::to_string(simTime().dbl()) + "," + convertToHexString(hashedId) +
            "," + vehicleId;
        Logger::log(logEntry);
    }
}

// namespace artery