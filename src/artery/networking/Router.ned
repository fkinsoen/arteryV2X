package artery.networking;

simple Router
{
    parameters:
        @class(Router);
        @signal[IdentityChanged](type=long);
        @signal[LinkReception](type=GeoNetPacket);

        @statistic[LinkLatency](source="messageAge(LinkReception)"; unit=s; record=vector?);

        string dccModule;
        string middlewareModule;
        string radioDriverModule;
        string runtimeModule;
        string securityModule;

        bool deferInitialBeacon = default(true);
        bool disableBeaconing = default(false);
        bool isMobile = default(true);

        // GN SDU size ceiling (vanetza MIB's itsGnMaxSduSize), exposed for the
        // capacity-relaxed elevated-revocation-rate attack. Default (1398) reproduces
        // vanetza's own MIB default exactly.
        int maxSduSize = default(1398);

    gates:
        input radioDriverData;
        input radioDriverProperties;
}
