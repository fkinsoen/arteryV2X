#ifndef ARTERY_JAMMERMARKERSERVICE_H_
#define ARTERY_JAMMERMARKERSERVICE_H_

#include "artery/application/ItsG5BaseService.h"
#include <string>

namespace artery
{

class JammerRegistry;

// Loaded (alongside a scheme's normal vehicle service) onto whichever node index is
// designated as the jamming-bubble attacker (same node-index/services-XML pattern A1
// uses). Carries no scheme-specific message logic of its own -- it exists only to
// register/unregister this vehicle's own ID with the shared JammerRegistry, which every
// other vehicle's baseline service then queries. One shared class works for all three
// schemes since registration itself has nothing scheme-specific about it.
class JammerMarkerService : public ItsG5BaseService
{
public:
    void initialize() override;
    void finish() override;
    bool requiresListener() const override { return false; }

private:
    JammerRegistry* mJammerRegistry = nullptr;
    std::string mVehicleId;
};

} // namespace artery

#endif /* ARTERY_JAMMERMARKERSERVICE_H_ */
