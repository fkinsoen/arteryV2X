#include "VehicleCRLService.h"

#include "CRLMessageHandler.h"
#include "CRLMessage_m.h"
#include "EnrollmentRequest_m.h"
#include "JammingCheck.h"
#include "PseudonymMessage_m.h"
#include "RevocationAuthorityService.h"
#include "V2VMessageHandler.h"
#include "V2VMessage_m.h"
#include "artery/envmod/GlobalEnvironmentModel.h"
#include "artery/envmod/EnvironmentModelObject.h"
#include "artery/envmod/JammerRegistry.h"
#include "artery/networking/GeoNetPacket.h"
#include "artery/traci/VehicleController.h"
#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"

#include <arpa/inet.h>
#include <inet/common/ModuleAccess.h>
#include <omnetpp.h>
#include <vanetza/btp/data_indication.hpp>
#include <vanetza/btp/data_request.hpp>
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

#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

Define_Module(artery::VehicleCRLService);

using namespace artery;
using namespace vanetza::security;
using namespace omnetpp;

namespace artery
{

const vanetza::ItsAid VehicleCRLService::ENROLLMENT_ITS_AID = 2;
const vanetza::ItsAid VehicleCRLService::V2V_ITS_AID = 36;

void VehicleCRLService::initialize()
{
    ItsG5Service::initialize();

    mBackend = std::unique_ptr<vanetza::security::BackendCryptoPP>(new vanetza::security::BackendCryptoPP());
    mKeyPair = mBackend->generate_key_pair();
    auto tempPseudonym = GenerateRoot(mKeyPair);

    mCRLHandler = std::unique_ptr<CRLMessageHandler>(new CRLMessageHandler(mBackend.get(), mKeyPair, tempPseudonym));
    mPseudonymHandler = std::unique_ptr<PseudonymMessageHandler>(new PseudonymMessageHandler(mBackend.get(), mKeyPair, tempPseudonym));

    // Mobile jamming bubble (default disabled -- reproduces pre-existing behavior exactly).
    // Module pointers are resolved lazily, only when actually enabled, so this class carries
    // no hard dependency on the envmod network for anyone running with jamming disabled.
    mJammingEnabled = par("jammingEnabled");
    if (mJammingEnabled) {
        mJammingRadius = par("jammingRadius").doubleValue() * boost::units::si::meter;
        mJammingTimingMode = par("jammingTimingMode").stdstringValue();
        mJammingT1 = par("jammingT1").doubleValue();
        mJammingT2 = par("jammingT2").doubleValue();
        mGlobalEnvironmentModel = inet::getModuleFromPar<GlobalEnvironmentModel>(par("globalEnvironmentModule"), findHost());
        mJammerRegistry = inet::getModuleFromPar<JammerRegistry>(par("jammerRegistryModule"), findHost());
    }

    std::cout << "VehicleCRLService initialized." << std::endl;
}

void VehicleCRLService::indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net)
{
    Enter_Method("indicate");

    if (!packet) {
        std::cout << "Received packet is nullptr. Ignoring." << std::endl;
        return;
    }

    if (auto* v2vMessage = dynamic_cast<V2VMessage*>(packet)) {
        // Peer-to-peer ground truth for the effective-revocation-time metric: jammed
        // separately from the scheme's own broadcast, under a distinct log tag, so a
        // censored reception here is never conflated with a scheme-level accept/reject.
        if (checkJammingBubble(packet->getClassName(), "JAM_CHECK_V2V_CENSORED")) {
            delete packet;
            return;
        }
        handleV2VMessage(v2vMessage);
    } else if (checkJammingBubble(packet->getClassName(), "JAM_CHECK")) {
        // Indiscriminate drop: covers the scheme's own broadcast (CRLMessage) and any other
        // non-metric-bearing message type this service receives (PseudonymMessage), closing
        // the message-type-selectivity gap without touching TransportDispatcher.
        delete packet;
        return;
    } else if (auto* crlMessage = dynamic_cast<CRLMessage*>(packet)) {
        handleCRLMessage(crlMessage);
    } else if (auto* pseudonymMessage = dynamic_cast<PseudonymMessage*>(packet)) {
        if (mState == VehicleState::ENROLLED) {
            delete pseudonymMessage;
            return;
        }
        handlePseudonymMessage(pseudonymMessage);
    } else {
        // std::cout << "Unknown message type. Ignoring." << std::endl;
    }

    delete packet;
}

void VehicleCRLService::trigger()
{
    Enter_Method("trigger");

    switch (mState) {
        case VehicleState::NOT_ENROLLED:
            sendEnrollmentRequest();
            mState = VehicleState::ENROLLMENT_REQUESTED;
            break;
        case VehicleState::ENROLLED:
            sendV2VMessage();
            break;
        default:
            // Do nothing while waiting for enrollment response
            break;
    }
}

void VehicleCRLService::handleCRLMessage(CRLMessage* crlMessage)
{
    if (!mCRLHandler->verifyCRLSignature(crlMessage)) {
        std::cout << "CRL message signature verification failed." << std::endl;
        return;
    }

    std::vector<vanetza::security::HashedId8> revokedCertificates;
    for (unsigned int i = 0; i < crlMessage->getMRevokedCertificatesArraySize(); ++i) {
        revokedCertificates.push_back(crlMessage->getMRevokedCertificates(i));
    }
    updateLocalCRL(revokedCertificates);

    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    Logger::log("CRL_RECEIVED," + std::to_string(simTime().dbl()) +
        "," + vehicle.getVehicleId() + "," + std::to_string(mLocalCRL.size()));
}

void VehicleCRLService::handlePseudonymMessage(PseudonymMessage* pseudonymMessage)
{
    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string currentVehicleId = vehicle.getVehicleId();

    if (pseudonymMessage->getPayload() != currentVehicleId) {
        return;
    }

    vanetza::security::Certificate newPseudonym = pseudonymMessage->getPseudonym();

    if (!mPseudonymHandler->verifyPseudonymSignature(pseudonymMessage)) {
        std::cout << "Invalid PseudonymMessage signature. Dropping message." << std::endl;
        return;
    }

    mPseudonymCertificate = newPseudonym;
    mV2VHandler = std::unique_ptr<V2VMessageHandler>(new V2VMessageHandler(mBackend.get(), mKeyPair, mPseudonymCertificate));
    mState = VehicleState::ENROLLED;
    std::cout << "Pseudonym updated for vehicle " << currentVehicleId << std::endl;
}

void VehicleCRLService::handleV2VMessage(V2VMessage* v2vMessage)
{
    simtime_t startTime = simTime();

    if (mState != VehicleState::ENROLLED) {
        std::cout << "Vehicle is not enrolled. Dropping message." << std::endl;
        return;
    }

    const vanetza::security::Certificate& cert = v2vMessage->getCertificate();
    vanetza::security::HashedId8 certHash = calculate_hash(cert);

    if (isRevoked(certHash)) {
        auto& vehicle = getFacilities().get_const<traci::VehicleController>();
        std::string receiverId = vehicle.getVehicleId();
        std::string senderId = v2vMessage->getPayload();

        std::cout << "=== MESSAGE DISCARDED ===" << std::endl
                  << "Receiving vehicle: " << receiverId << std::endl
                  << "Sender's certificate is revoked. Dropping message from vehicle " << senderId << std::endl
                  << "=========================" << std::endl;

        std::string logEntry = "MESSSAGE_DISCARDED," + std::to_string(simTime().dbl()) + "," + convertToHexString(certHash);
        Logger::log(logEntry);
        return;
    }

    if (!mV2VHandler->verifyV2VSignature(v2vMessage)) {
        std::cout << "Invalid signature. Dropping message." << std::endl;
    }

    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string id = vehicle.getVehicleId();
    // std::cout << "Vehicle " << id << " got V2V from " << v2vMessage->getPayload() << std::endl;

    Logger::log("MESSAGE_ACCEPTED," + std::to_string(simTime().dbl()) +
        "," + convertToHexString(certHash) + "," + id);
}

bool VehicleCRLService::checkJammingBubble(const std::string& messageType, const std::string& logTag)
{
    if (!mJammingEnabled) {
        return false;
    }

    double now = simTime().dbl();
    bool windowActive = (mJammingTimingMode == "alwaysOn") || (now >= mJammingT1 && now <= mJammingT2);
    if (!windowActive) {
        return false;
    }

    auto& receiverVehicle = getFacilities().get_const<traci::VehicleController>();
    std::string receiverId = receiverVehicle.getVehicleId();
    artery::Position receiverPos = receiverVehicle.getPosition();

    bool jammed = false;
    for (const auto& jammerId : mJammerRegistry->getJammerIds()) {
        if (jammerId == receiverId) {
            continue; // jammer does not jam itself
        }

        auto jammerObject = mGlobalEnvironmentModel->getObject(jammerId);
        if (!jammerObject) {
            continue; // jammer vehicle not currently in the simulation
        }

        artery::Position jammerPos = jammerObject->getCentrePoint();
        vanetza::units::Length distance = jammingDistance(receiverPos, jammerPos);
        bool inside = isWithinJammingRadius(receiverPos, jammerPos, mJammingRadius);

        Logger::log(logTag + "," + std::to_string(now) + "," + receiverId + "," +
            std::to_string(receiverPos.x.value()) + "," + std::to_string(receiverPos.y.value()) + "," +
            jammerId + "," +
            std::to_string(jammerPos.x.value()) + "," + std::to_string(jammerPos.y.value()) + "," +
            std::to_string(distance.value()) + "," + (inside ? "DROP" : "PASS") + "," + messageType);

        if (inside) {
            jammed = true;
            // keep looping: still log every jammer's distance/outcome for this reception
        }
    }

    return jammed;
}

void VehicleCRLService::updateLocalCRL(const std::vector<vanetza::security::HashedId8>& revokedCertificates)
{
    mLocalCRL.insert(mLocalCRL.end(), revokedCertificates.begin(), revokedCertificates.end());
    std::sort(mLocalCRL.begin(), mLocalCRL.end());
    mLocalCRL.erase(std::unique(mLocalCRL.begin(), mLocalCRL.end()), mLocalCRL.end());
}

bool VehicleCRLService::isRevoked(const vanetza::security::HashedId8& certificateHash) const
{
    return std::binary_search(mLocalCRL.begin(), mLocalCRL.end(), certificateHash);
}

void VehicleCRLService::sendEnrollmentRequest()
{
    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string id = vehicle.getVehicleId();

    EnrollmentRequest* enrollmentRequest = new EnrollmentRequest();
    enrollmentRequest->setVehicleId(id.c_str());
    enrollmentRequest->setPublicKey(mKeyPair.public_key);

    vanetza::btp::DataRequestB req;
    req.destination_port = vanetza::host_cast(getPortNumber());
    req.gn.transport_type = vanetza::geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(vanetza::dcc::Profile::DP3));
    req.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    req.gn.its_aid = ENROLLMENT_ITS_AID;

    request(req, enrollmentRequest);
    std::cout << "Enrollment request sent from: " << id << std::endl;
}

void VehicleCRLService::sendV2VMessage()
{
    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string id = vehicle.getVehicleId();

    vanetza::btp::DataRequestB req;
    req.destination_port = vanetza::host_cast(getPortNumber());
    req.gn.transport_type = vanetza::geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(vanetza::dcc::Profile::DP3));
    req.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    req.gn.its_aid = V2V_ITS_AID;

    V2VMessage* v2vMessage = mV2VHandler->createV2VMessage(id);
    v2vMessage->setCertificate(mPseudonymCertificate);
    request(req, v2vMessage);
    // std::cout << "V2V message sent." << std::endl;
}

void VehicleCRLService::handleMessage(omnetpp::cMessage* msg)
{
    if (strcmp(msg->getName(), "triggerEvent") == 0) {
        trigger();
        delete msg;
    } else {
        ItsG5Service::handleMessage(msg);
    }
}

std::string VehicleCRLService::convertToHexString(const vanetza::security::HashedId8& hashedId)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : hashedId) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

}  // namespace artery