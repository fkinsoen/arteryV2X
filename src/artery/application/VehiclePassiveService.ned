package artery.application;

simple VehiclePassiveService like ItsG5Service
{
    parameters:
        // Mobile jamming bubble attack: default disabled, reproduces pre-existing behavior
        // exactly (regression-safe, same discipline as A1's attackerShare=0 default).
        bool jammingEnabled = default(false);
        double jammingRadius @unit(m) = default(100m);
        // "alwaysOn": jammer jams for its entire time in the simulation.
        // "boundedWindow": jammer jams only during [jammingT1, jammingT2] (absolute sim time).
        string jammingTimingMode = default("alwaysOn");
        double jammingT1 @unit(s) = default(0s);
        double jammingT2 @unit(s) = default(0s);
        string globalEnvironmentModule = default("environmentModel");
        string jammerRegistryModule = default("jammerRegistry");
}
