package artery.application;

simple SelfRevocationAuthService
{
    parameters:
        @class(SelfRevocationAuthService);
        double validityWindow @unit(s) = default(50s);
        double heartbeatInterval @unit(s) = default(3s);
        double minRevocationInterval @unit(s) = default(40s);
        double maxRevocationInterval @unit(s) = default(80s);
        double dropProbability = default(0.35);
        double delayProbability = default(0.35);
        double delayMean @unit(s) = default(2s);
        double delayStdDev @unit(s) = default(0.3s);
        string revocationMode = default("interval");

        // Capacity-relaxed elevated-revocation-rate attack: entry-cap truncation logic
        // itself is unchanged, this only makes the threshold configurable. Default (112)
        // reproduces the previous hardcoded behavior exactly.
        int maxPrlEntries = default(112);
        // Path to the Router module whose maxSduSize this module's consistency check reads
        // LIVE at initialize() -- same routerModule/getModuleFromPar<Router> pattern already
        // used by LocationTableLogger.ned/.cc, not a hand-duplicated shadow value.
        string routerModule = default(".vanetza[0].router");
}
