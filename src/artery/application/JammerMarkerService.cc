#include "artery/application/JammerMarkerService.h"
#include "artery/envmod/JammerRegistry.h"
#include "artery/traci/VehicleController.h"
#include "Logger.h"

#include <inet/common/ModuleAccess.h>
#include <omnetpp.h>

Define_Module(artery::JammerMarkerService)

namespace artery
{

void JammerMarkerService::initialize()
{
    ItsG5BaseService::initialize();

    mJammerRegistry = inet::getModuleFromPar<JammerRegistry>(par("jammerRegistryModule"), findHost());
    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    mVehicleId = vehicle.getVehicleId();
    mJammerRegistry->registerJammer(mVehicleId);

    Logger::log("JAMMER_REGISTERED," + std::to_string(omnetpp::simTime().dbl()) + "," + mVehicleId);
}

void JammerMarkerService::finish()
{
    if (mJammerRegistry) {
        mJammerRegistry->unregisterJammer(mVehicleId);
        Logger::log("JAMMER_UNREGISTERED," + std::to_string(omnetpp::simTime().dbl()) + "," + mVehicleId);
    }
    ItsG5BaseService::finish();
}

} // namespace artery
