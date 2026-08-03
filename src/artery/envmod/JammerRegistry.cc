#include "artery/envmod/JammerRegistry.h"

Define_Module(artery::JammerRegistry)

namespace artery
{

void JammerRegistry::registerJammer(const std::string& vehicleId)
{
    mJammerIds.insert(vehicleId);
}

void JammerRegistry::unregisterJammer(const std::string& vehicleId)
{
    mJammerIds.erase(vehicleId);
}

std::set<std::string> JammerRegistry::getJammerIds() const
{
    return mJammerIds;
}

} // namespace artery
