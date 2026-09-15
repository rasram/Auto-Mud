# network/sdn/

**Owner:** Anand Mahadev

The Ryu SDN controller. It receives response decisions from the Decision Engine (`integration/decision_engine/`) and pushes the matching OpenFlow rules to Open vSwitch: rate limit, VLAN isolation (quarantine), or full block.

Methodology: Stage 3, step 13.
