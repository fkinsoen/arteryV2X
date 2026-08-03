#ifndef ARTERY_JAMMERREGISTRY_H_
#define ARTERY_JAMMERREGISTRY_H_

#include <omnetpp/csimplemodule.h>
#include <set>
#include <string>

namespace artery
{

// Single, network-level module (like GlobalEnvironmentModel/IdentityRegistry) recording
// which currently-simulated vehicle IDs carry the mobile-jamming-bubble capability.
// JammerMarkerService registers/unregisters itself here at spawn/departure; any vehicle's
// baseline service can query it to find out which vehicle ID(s) to look up in
// GlobalEnvironmentModel for the jamming-radius check.
class JammerRegistry : public omnetpp::cSimpleModule
{
public:
    void registerJammer(const std::string& vehicleId);
    void unregisterJammer(const std::string& vehicleId);
    std::set<std::string> getJammerIds() const;

private:
    std::set<std::string> mJammerIds;
};

} // namespace artery

#endif /* ARTERY_JAMMERREGISTRY_H_ */
