# Profiling implementation decision

Commits `262076f` and `f9d9df6` introduced a PCAP-to-MUD ACL generator and a
Zeek window behavioral profiler, respectively. The Zeek implementation is the
maintained profiling path. It has a frozen 60-second baseline and deviation
scorer, with 27 committed device profiles. The PCAP generator, its derived MUD
ACLs, and its separate scoring path were removed during cleanup.

Before removal, the seven devices with both stored outputs were compared
against the same MUDgee domain, port, and network facts. The Zeek profiles
recovered **69/78 (88.5%)** facts; the PCAP-generated ACLs recovered
**54/78 (69.2%)**. This was reference-fact recall only. It did not measure
false allowances, anomaly detection, or identical source-capture provenance.
The PCAP output was an ACL document while the Zeek output is an observation
and deviation profile, so their other reported percentages are not directly
comparable.

The PCAP packet reader did not provide a useful drop-in improvement for the
Zeek flow pipeline without introducing a second ingestion contract. The
comparison did identify two Zeek issues that were fixed: destination ports
were dropped before window scoring, and certificate names could be attributed
across devices. The committed Zeek profiles predate these fixes; full Zeek
intermediates are absent here, so revised corpus metrics require regeneration.
No held-out real-attack detection or false-positive result has been measured.
