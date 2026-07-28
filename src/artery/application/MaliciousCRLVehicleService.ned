package artery.application;

simple MaliciousCRLVehicleService extends VehicleCRLService
{
    parameters:
        @class(MaliciousCRLVehicleService);
        double attackerShare = default(0);
}
