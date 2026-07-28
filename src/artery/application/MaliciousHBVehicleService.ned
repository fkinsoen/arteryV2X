package artery.application;

simple MaliciousHBVehicleService extends VehicleHBService
{
    parameters:
        @class(MaliciousHBVehicleService);
        double attackerShare = default(0);
}
