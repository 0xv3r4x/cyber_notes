# Endpoint Detection and Response (EDR)

**EDR** is an integrated endpoint security solution that combines real-time continuous monitoring and collection of endpoint data with rule-based automated response and analysis capabilities.

EDR solutions:
- CarbonBlack
- SentinelOne
- FireEye HX

If we suspect a machine has been compromised, we must isolate it from the rest of the network in order to stop the attacker's connection to the internal network, thus preventing lateral movement.

The compromised machine should be cut off from internal/external networks and should only be connected to the EDR centre so that we can continue the analysis.  You can also perform a search on other endpoints to determine who has been affected by an attack - for example, if you have a file with a given hash, you can search for it on other devices to see if it was executed.