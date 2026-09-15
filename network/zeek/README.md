# network/zeek/

**Owner:** Anand Mahadev

Zeek sensor setup. All OVS traffic is mirrored to Zeek, which writes structured flow logs roughly every 60 seconds. The same Zeek flow format is used for the offline UNSW PCAP replay in Stage 0, so live features stay consistent with training features.

Methodology: Stage 0, step 2 (offline replay) and Stage 1, step 8 (live sensor).
