#ifndef ARTERY_JAMMINGCHECK_H_
#define ARTERY_JAMMINGCHECK_H_

#include "artery/utility/Geometry.h"
#include <vanetza/geonet/areas.hpp>
#include <cmath>

namespace artery
{

// Straight-line distance between two Cartesian (ENU, meters) positions -- reuses vanetza's
// own CartesianPosition subtraction operator rather than hand-rolling dx/dy bookkeeping.
inline vanetza::units::Length jammingDistance(const Position& receiver, const Position& jammer)
{
    vanetza::geonet::CartesianPosition receiverPos(receiver.x, receiver.y);
    vanetza::geonet::CartesianPosition jammerPos(jammer.x, jammer.y);
    vanetza::geonet::CartesianPosition relative = receiverPos - jammerPos;
    double dx = relative.x.value();
    double dy = relative.y.value();
    return std::sqrt(dx * dx + dy * dy) * boost::units::si::meter;
}

// True if `receiver` is inside or exactly at the border of a circle of the given radius
// centred on `jammer`. Reuses vanetza's own geonet::Circle + geometric_function -- the same
// area construct already used for GeoBroadcast/GeoAnycast destinations elsewhere in this
// codebase (GbcMockService.cc) -- rather than a hand-rolled radius comparison, evaluated
// directly in Cartesian coordinates since that's GlobalEnvironmentModel's native frame
// (EnvironmentModelObject::getCentrePoint() / VehicleController::getPosition()).
inline bool isWithinJammingRadius(const Position& receiver, const Position& jammer, vanetza::units::Length radius)
{
    vanetza::geonet::CartesianPosition receiverPos(receiver.x, receiver.y);
    vanetza::geonet::CartesianPosition jammerPos(jammer.x, jammer.y);
    vanetza::geonet::CartesianPosition relative = receiverPos - jammerPos;

    vanetza::geonet::Circle circle;
    circle.r = radius;

    return vanetza::geonet::geometric_function(circle, relative) >= 0.0;
}

} // namespace artery

#endif /* ARTERY_JAMMINGCHECK_H_ */
