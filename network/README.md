# network/ — Network Infrastructure

**Owner:** Anand Mahadev

Everything that makes up the emulated home network and acts on it: the Mininet + Open vSwitch testbed, the Zeek sensor, attack injection, and SDN enforcement through Ryu.

| Subdirectory | Contents |
|---|---|
| `testbed/` | Mininet topology and Open vSwitch setup (Stage 1, step 6) |
| `zeek/` | Zeek sensor config and OVS traffic mirroring (Stage 1, step 8) |
| `attacks/` | Attack simulations for the four target classes (Stage 4, step 15) |
| `sdn/` | Ryu controller that turns decisions into OpenFlow rules on OVS (Stage 3, step 13) |

See `docs/AutoMUD_Project_Context.md` §7 and §8.
