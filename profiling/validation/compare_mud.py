"""
compare_mud.py

Objective 1: how much of a hand-authored MUD profile does our automatically
generated profile recover?

MUDgee's profiles (the UNSW ground truth) express what a device is allowed to
do as IETF MUD ACL rules. This script pulls the checkable facts out of those
rules and asks, for each one, whether our generated profile saw it:

  domain   -- ietf-acldns:dst-dnsname / src-dnsname. Matched against the
              domains the device queried in dns.log, plus TLS server names
              from ssl.log/x509.log. A rule also counts as matched when the
              observed name is a sub-domain of the MUD name or vice versa
              (MUD says pool.ntp.org, the device asked uk.pool.ntp.org).
  port     -- tcp/udp destination-port and source-port. Matched against the
              destination ports observed in conn.log. Source ports appear in
              to-device rules, where the server's port is the port our
              outbound flow was addressed to, so both collapse to the same
              check.
  network  -- destination-ipv4-network / source-ipv4-network, mostly multicast
              ranges. Matched when any observed destination IP falls inside.

Two rule kinds are counted but deliberately excluded from the headline score,
because they describe permissions rather than endpoints and nothing in packet
metadata can confirm or deny them:

  local-networks -- "may talk to anything on the LAN"
  controller     -- "may talk to whichever device fills this role"

Each is reported separately, alongside whether the device was seen talking on
the LAN at all, so the exclusion stays visible rather than quietly inflating
the score.

Usage:
    python profiling/validation/compare_mud.py \
        --profiles data/processed/unsw/behavioral_profiles \
        --mud-dir data/references/mudgee_muds \
        --out data/processed/unsw/reports/zeek_reference_fact_recall.json
"""

import argparse
import ipaddress
import json
from collections import Counter
from pathlib import Path

# Generated profile stem -> MUDgee ground-truth filename. MUDgee's names are
# neither the device names nor consistently cased, so the mapping is explicit.
DEVICE_TO_MUD = {
    "AmazonEcho": "amazonEchoMud.json",
    "AugustDoorBell": "augustdoorbellcamMud.json",
    "AwairAirQuality": "awairAirQualityMud.json",
    "BelkinCamera": "belkincameraMud.json",
    "BelkinWemoMotionSensor": "wemomotionMud.json",
    "BelkinWemoSwitch": "wemoswitchMud.json",
    "BlipCareBPMeter": "blipcareBPmeterMud.json",
    "CanaryCamera": "canaryCameraMud.json",
    "HelloBarbie": "hellobarbieMud.json",
    "HPPrinter": "hpprinterMud.json",
    "iHome": "ihomepowerplugMud.json",
    "LiFXBulb": "lifxbulbMud.json",
    "NestDropCam": "dropcamMud.json",
    "NestProtectSmokeAlarm": "nestsmokesensorMud.json",
    "NetatmoWeatherStation": "NetatmoWeatherStationMud.json",
    "NetatmoWelcome": "NetatmoCameraMud.json",
    "PhilipsHue": "HueBulbMud.json",
    "PixStarPhotoFrame": "pixstarphotoframeMud.json",
    "RingDoorBell": "ringdoorbellMud.json",
    "SamsungCamera": "samsungsmartcamMud.json",
    "SamsungSmartThings": "SmartThingsMud.json",
    "TPLinkCamera": "tplinkcameraMud.json",
    "TPLinkSmartPlug": "tplinkplugMud.json",
    "TribySpeaker": "tribyspeakerMud.json",
    "WithingsBabyMonitor": "withingsbabymonitorMud.json",
    "WithingsSleepSensor": "withingssleepsensorMud.json",
    "WithingsSmartScale": "withingscardioMud.json",
}

IP_PROTOCOL_NAMES = {6: "tcp", 17: "udp", 1: "icmp"}


def extract_mud_facts(mud):
    """Pull checkable endpoint facts out of one MUD profile."""
    domains, ports, networks = set(), set(), set()
    permissions = Counter()

    for acl in mud["ietf-access-control-list:access-lists"]["acl"]:
        for ace in acl["aces"]["ace"]:
            matches = ace.get("matches", {})
            ip_protocol = None
            for layer in ("ipv4", "ipv6"):
                if isinstance(matches.get(layer), dict):
                    ip_protocol = matches[layer].get("protocol", ip_protocol)

            for layer, fields in matches.items():
                if not isinstance(fields, dict):
                    continue

                for key, value in fields.items():
                    if "dnsname" in key:
                        domains.add(value.lower())
                    elif key in ("destination-ipv4-network", "source-ipv4-network",
                                 "destination-ipv6-network", "source-ipv6-network"):
                        networks.add(value)
                    elif key in ("local-networks", "controller"):
                        permissions[key] += 1
                    elif key in ("destination-port", "source-port"):
                        if isinstance(value, dict) and "port" in value:
                            proto = layer if layer in ("tcp", "udp") else \
                                IP_PROTOCOL_NAMES.get(ip_protocol, layer)
                            ports.add(f"{proto}/{value['port']}")

    return {
        "domains": sorted(domains),
        "ports": sorted(ports),
        "networks": sorted(networks),
        "permissions": dict(permissions),
    }


def domain_matches(mud_domain, observed):
    """True when the device was seen using this domain, or a relative of it."""
    if mud_domain in observed:
        return True
    return any(
        name.endswith("." + mud_domain) or mud_domain.endswith("." + name)
        for name in observed
    )


def network_matches(network, observed_ips):
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False
    for raw in observed_ips:
        try:
            if ipaddress.ip_address(raw) in net:
                return True
        except ValueError:
            continue
    return False


def compare(profile, mud_facts):
    """Score one generated profile against one MUD profile's facts."""
    endpoints = profile["endpoints"]
    observed_names = set(endpoints["domains"]) | set(endpoints["tls_server_names"])
    # Ports the device dialled out to and ports it served on: MUD's from-device
    # and to-device rules cover both directions.
    observed_ports = set(endpoints["destination_ports"]) | set(endpoints.get("listening_ports", {}))
    observed_ips = set(endpoints["destination_ips"]) | set(endpoints.get("source_ips", {}))

    matched_domains = [d for d in mud_facts["domains"] if domain_matches(d, observed_names)]
    matched_ports = [p for p in mud_facts["ports"] if p in observed_ports]
    matched_networks = [n for n in mud_facts["networks"] if network_matches(n, observed_ips)]

    checkable = len(mud_facts["domains"]) + len(mud_facts["ports"]) + len(mud_facts["networks"])
    matched = len(matched_domains) + len(matched_ports) + len(matched_networks)

    talks_on_lan = any(
        ipaddress.ip_address(ip).is_private
        for ip in observed_ips
        if _is_ip(ip)
    )

    def rate(part, whole):
        return (len(part) / whole) if whole else None

    return {
        "device": profile["device"],
        "fidelity": (matched / checkable) if checkable else None,
        "matched": matched,
        "checkable": checkable,
        "domains": {
            "total": len(mud_facts["domains"]),
            "matched": len(matched_domains),
            "rate": rate(matched_domains, len(mud_facts["domains"])),
            "missed": sorted(set(mud_facts["domains"]) - set(matched_domains)),
        },
        "ports": {
            "total": len(mud_facts["ports"]),
            "matched": len(matched_ports),
            "rate": rate(matched_ports, len(mud_facts["ports"])),
            "missed": sorted(set(mud_facts["ports"]) - set(matched_ports)),
        },
        "networks": {
            "total": len(mud_facts["networks"]),
            "matched": len(matched_networks),
            "rate": rate(matched_networks, len(mud_facts["networks"])),
            "missed": sorted(set(mud_facts["networks"]) - set(matched_networks)),
        },
        "not_scored": {
            "local_network_rules": mud_facts["permissions"].get("local-networks", 0),
            "controller_rules": mud_facts["permissions"].get("controller", 0),
            "device_talks_on_lan": talks_on_lan,
        },
        "observed_beyond_mud": {
            "domains": sorted(
                name for name in observed_names
                if not any(domain_matches(m, {name}) for m in mud_facts["domains"])
            ),
            "ports": sorted(observed_ports - set(mud_facts["ports"])),
        },
    }


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Objective 1: score generated profiles against MUDgee ground truth."
    )
    parser.add_argument("--profiles", required=True, type=Path,
                        help="Directory of generated profile JSONs.")
    parser.add_argument("--mud-dir", required=True, type=Path,
                        help="Directory of MUDgee ground-truth JSONs.")
    parser.add_argument("--out", type=Path, default=None,
                        help="Write the full report here as JSON.")
    args = parser.parse_args()

    results, skipped = [], []
    for path in sorted(args.profiles.glob("*.json")):
        mud_name = DEVICE_TO_MUD.get(path.stem)
        if mud_name is None:
            skipped.append((path.stem, "no MUD profile mapping"))
            continue
        mud_path = args.mud_dir / mud_name
        if not mud_path.exists():
            skipped.append((path.stem, f"missing {mud_name}"))
            continue

        profile = json.loads(path.read_text())
        facts = extract_mud_facts(json.loads(mud_path.read_text()))
        results.append(compare(profile, facts))

    if not results:
        raise SystemExit("No profiles could be compared.")

    scored = [r for r in results if r["fidelity"] is not None]
    overall = {
        "devices": len(scored),
        "matched": sum(r["matched"] for r in scored),
        "checkable": sum(r["checkable"] for r in scored),
    }
    overall["fidelity_micro"] = overall["matched"] / overall["checkable"]
    overall["fidelity_macro"] = sum(r["fidelity"] for r in scored) / len(scored)

    header = f"{'device':24s} {'fidelity':>9s} {'domains':>12s} {'ports':>10s} {'networks':>10s}"
    print(header)
    print("-" * len(header))
    for r in sorted(results, key=lambda r: r["fidelity"] or 0, reverse=True):
        def cell(part):
            return f"{part['matched']}/{part['total']}"
        print(f"{r['device'][:24]:24s} {r['fidelity']:>8.1%} "
              f"{cell(r['domains']):>12s} {cell(r['ports']):>10s} {cell(r['networks']):>10s}")
    print("-" * len(header))
    print(f"{'OVERALL':24s} {overall['fidelity_micro']:>8.1%} "
          f"({overall['matched']}/{overall['checkable']} rules, "
          f"macro {overall['fidelity_macro']:.1%}, {overall['devices']} devices)")
    for name, reason in skipped:
        print(f"  skipped {name}: {reason}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(
            {"overall": overall, "devices": results, "skipped": skipped}, indent=2
        ))
        print(f"\nreport -> {args.out}")


if __name__ == "__main__":
    main()
