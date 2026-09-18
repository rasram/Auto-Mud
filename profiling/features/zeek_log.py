"""
zeek_log.py

Reader for Zeek's TSV logs (conn.log, dns.log, ssl.log, x509.log).

This is the single entry point the profiling engine uses to get at traffic,
so that offline replays (UNSW PCAPs -> zeek -r) and the live testbed sensor
produce the same records. Nothing downstream of this module knows whether a
flow came from a 2016 capture or from Mininet.

Device identity is keyed on MAC, not IP: a device keeps its MAC across DHCP
lease changes, and every UNSW capture we looked at shows the same device
under two or more addresses.

Requires conn.log written with the mac-logging policy:
    zeek -r <file>.pcap policy/protocols/conn/mac-logging
"""

from pathlib import Path


# Zeek writes "-" for unset and "(empty)" for empty containers.
UNSET = {"-", "(empty)", ""}

# conn.log fields the profiling engine consumes, with their converters.
# Anything else in the log is carried through untouched as a string.
CONN_NUMERIC = {
    "ts": float,
    "duration": float,
    "id.orig_p": int,
    "id.resp_p": int,
    "orig_bytes": int,
    "resp_bytes": int,
    "orig_pkts": int,
    "resp_pkts": int,
    "orig_ip_bytes": int,
    "resp_ip_bytes": int,
}

# conn_state values that mean the TCP handshake never completed. Used for the
# failure-ratio feature. UDP is excluded by the caller: DNS/NTP flows are
# logged S0 whenever the capture holds no reply, which is most of the time.
TCP_FAILED_STATES = {"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR"}


def read_log(path):
    """Yield one dict per record in a Zeek TSV log.

    Returns nothing if the log does not exist -- Zeek only writes a log when
    the capture contained that protocol, so a missing dns.log is normal.
    """
    path = Path(path)
    if not path.exists():
        return

    fields = None
    with path.open(errors="replace") as handle:
        for line in handle:
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                continue
            if fields is None:
                continue
            values = line.rstrip("\n").split("\t")
            yield dict(zip(fields, values))


def _coerce(record, converters):
    """Apply numeric converters in place, mapping unset values to None."""
    for key, convert in converters.items():
        if key not in record:
            continue
        raw = record[key]
        if raw in UNSET:
            record[key] = None
            continue
        try:
            record[key] = convert(raw)
        except ValueError:
            record[key] = None
    return record


def _involves(record, mac):
    return mac is None or mac in (record.get("orig_l2_addr"), record.get("resp_l2_addr"))


def read_conn(zeek_dir, mac=None, initiated_only=True):
    """Read conn.log as flow records for one device.

    mac              -- device MAC; None reads every host in the capture.
    initiated_only   -- keep only flows the device originated. Inbound flows
                        are a separate signal and are deliberately not mixed
                        into per-device volume features.
    """
    for record in read_log(Path(zeek_dir) / "conn.log"):
        if not _involves(record, mac):
            continue
        if initiated_only and mac is not None and record.get("orig_l2_addr") != mac:
            continue
        yield _coerce(record, CONN_NUMERIC)


def device_ips(zeek_dir, mac):
    """Return every IP the device originated traffic from, per conn.log.

    Only conn.log carries MAC columns (that is all the mac-logging policy
    adds), so every other log has to be filtered by IP instead. A device holds
    several IPs over a long capture as DHCP leases turn over, which is exactly
    why identity is keyed on MAC and the IP set is derived rather than assumed.
    """
    return {
        record["id.orig_h"]
        for record in read_conn(zeek_dir, mac=mac)
        if record.get("id.orig_h") not in UNSET
    }


# Query suffixes that name something on the local segment rather than an
# endpoint the device talks to: mDNS service discovery (_ssh._tcp.local,
# printer.local) and reverse lookups (1.168.192.in-addr.arpa). They are real
# traffic, but counting them as endpoints inflates domain entropy and makes
# every ordinary service announcement look like a new destination.
NON_ENDPOINT_SUFFIXES = (".local", ".arpa")


def is_endpoint_domain(name):
    """False for mDNS and reverse-lookup names (see NON_ENDPOINT_SUFFIXES)."""
    return not name.endswith(NON_ENDPOINT_SUFFIXES)


def read_dns_queries(zeek_dir, ips=None, endpoints_only=True):
    """Read dns.log as (ts, query) pairs for one device.

    Filtered by the device's IP set (see device_ips) because dns.log has no
    MAC columns. The UNSW captures hold queries but no answers, so this is a
    stream of domain names the device asked for -- not an IP-to-domain
    mapping. Domain entropy is computed over this stream.
    """
    for record in read_log(Path(zeek_dir) / "dns.log"):
        if ips is not None and record.get("id.orig_h") not in ips:
            continue
        query = record.get("query")
        if query in UNSET or query is None:
            continue
        try:
            ts = float(record["ts"])
        except (KeyError, ValueError):
            continue
        query = query.lower()
        if endpoints_only and not is_endpoint_domain(query):
            continue
        yield ts, query


def read_tls_server_names(zeek_dir, ips=None):
    """Yield server names a device's TLS connections presented.

    Two sources, because IoT devices frequently omit SNI: ssl.log's
    server_name, and the CN of the server certificate in x509.log. Used as a
    second endpoint source for the MUD comparison, not as a window feature.
    x509 records carry no addresses and are not filtered.
    """
    for record in read_log(Path(zeek_dir) / "ssl.log"):
        if ips is not None and record.get("id.orig_h") not in ips:
            continue
        name = record.get("server_name")
        if name not in UNSET and name is not None:
            yield name.lower()

    for record in read_log(Path(zeek_dir) / "x509.log"):
        subject = record.get("certificate.subject", "")
        for part in subject.split(","):
            part = part.strip()
            if part.startswith("CN="):
                cn = part[3:].strip().lower().lstrip("*.")
                # x509.log holds every certificate in the chain, so most CNs
                # are CA names ("symantec class 3 secure server ca - g4")
                # rather than endpoints. Keep only CNs shaped like hostnames.
                if cn and looks_like_hostname(cn):
                    yield cn


def looks_like_hostname(value):
    """True for dotted names with a plausible TLD and no whitespace."""
    if not value or " " in value or "." not in value:
        return False
    label = value.rsplit(".", 1)[-1]
    return len(label) >= 2 and label.isalpha()


def device_mac_from_name(name):
    """Turn a UNSW pcap/device name into a MAC.

    'TPLinkSmartPlug_50c7bf005639' -> '50:c7:bf:00:56:39'
    Returns None if the name carries no MAC suffix.
    """
    tail = str(name).split("_")[-1].split(".")[0]
    if len(tail) != 12:
        return None
    try:
        int(tail, 16)
    except ValueError:
        return None
    return ":".join(tail[i:i + 2] for i in range(0, 12, 2)).lower()
