#!/usr/bin/env python3

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path


EXPECTED_SIZE = 2667
MAGIC = b"#y#y"

# ----------------------------------------------------------------------
# Known HORACO configuration layout
# ----------------------------------------------------------------------

# Management configuration
DHCP_OFFSET = 0x04
IP_OFFSET = 0x05
MASK_OFFSET = 0x09
GW_OFFSET = 0x0D

# Account / credential area.
# Treat the entire region as sensitive until fully decoded.
SECRET_START = 0x17
SECRET_END = 0x4D  # exclusive

# Per-port PVID table
PVID_OFFSET = 0x530
PVID_COUNT = 9

# VLAN records
VLAN_OFFSET = 0x58E
VLAN_RECORD_SIZE = 26
VLAN_RECORD_COUNT = 7

VID_OFFSET = 0
NAME_OFFSET = 2
NAME_LEN = 16
META_OFFSET = 18
META_LEN = 8


# ----------------------------------------------------------------------
# Utility functions
# ----------------------------------------------------------------------

def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_bin(path):
    data = Path(path).read_bytes()

    if len(data) != EXPECTED_SIZE:
        raise ValueError(
            f"Unexpected file size: {len(data)} bytes "
            f"(expected {EXPECTED_SIZE})"
        )

    if data[:4] != MAGIC:
        raise ValueError(
            f"Unexpected magic: {data[:4]!r} "
            f"(expected {MAGIC!r})"
        )

    return data


def ipv4(raw):
    return str(ipaddress.IPv4Address(bytes(raw)))


def ipv4_bytes(address):
    return ipaddress.IPv4Address(address).packed


def parse_hex_metadata(value):
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            f"Invalid metadata_hex value: {value!r}"
        ) from exc

    if len(raw) != META_LEN:
        raise ValueError(
            f"VLAN metadata must be exactly {META_LEN} bytes; "
            f"got {len(raw)}"
        )

    return raw


# ----------------------------------------------------------------------
# VLAN decoding
# ----------------------------------------------------------------------

def decode_vlan_record(data, index):
    pos = VLAN_OFFSET + index * VLAN_RECORD_SIZE
    rec = data[pos:pos + VLAN_RECORD_SIZE]

    if len(rec) != VLAN_RECORD_SIZE:
        raise ValueError(
            f"VLAN record {index} is incomplete "
            f"at offset 0x{pos:04x}"
        )

    vid = int.from_bytes(
        rec[VID_OFFSET:VID_OFFSET + 2],
        byteorder="big",
    )

    name_raw = rec[
        NAME_OFFSET:NAME_OFFSET + NAME_LEN
    ]

    name = (
        name_raw
        .split(b"\x00", 1)[0]
        .decode("ascii", errors="replace")
    )

    metadata = rec[
        META_OFFSET:META_OFFSET + META_LEN
    ]

    return {
        "index": index,
        "offset": f"0x{pos:04x}",
        "id": vid,
        "name": name,
        "metadata_hex": metadata.hex(),
        "raw_hex": rec.hex(),
    }


# ----------------------------------------------------------------------
# Decode
# ----------------------------------------------------------------------

def decode(path, outdir):
    data = load_bin(path)

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------------------
    # Sensitive account region
    # --------------------------------------------------------------

    secret = data[SECRET_START:SECRET_END]

    secret_path = outdir / "secrets.bin"
    secret_path.write_bytes(secret)

    # --------------------------------------------------------------
    # Sanitized binary template
    #
    # Everything remains byte-for-byte identical except the account
    # region, which is zeroed.
    # --------------------------------------------------------------

    template = bytearray(data)

    template[SECRET_START:SECRET_END] = (
        b"\x00" * (SECRET_END - SECRET_START)
    )

    template_path = outdir / "template.bin"
    template_path.write_bytes(template)

    # --------------------------------------------------------------
    # Management
    # --------------------------------------------------------------

    management = {
        "dhcp_raw": data[DHCP_OFFSET],
        "dhcp": bool(data[DHCP_OFFSET]),
        "address": ipv4(
            data[IP_OFFSET:IP_OFFSET + 4]
        ),
        "netmask": ipv4(
            data[MASK_OFFSET:MASK_OFFSET + 4]
        ),
        "gateway": ipv4(
            data[GW_OFFSET:GW_OFFSET + 4]
        ),
    }

    # --------------------------------------------------------------
    # PVIDs
    # --------------------------------------------------------------

    pvids = []

    for i in range(PVID_COUNT):
        pos = PVID_OFFSET + i * 2

        value = int.from_bytes(
            data[pos:pos + 2],
            byteorder="big",
        )

        pvids.append({
            "raw_index": i,
            "offset": f"0x{pos:04x}",
            "pvid": value,
        })

    # --------------------------------------------------------------
    # VLANs
    # --------------------------------------------------------------

    vlans = []

    for i in range(VLAN_RECORD_COUNT):
        vlans.append(
            decode_vlan_record(data, i)
        )

    # --------------------------------------------------------------
    # Readable config
    # --------------------------------------------------------------

    config = {
        "format": {
            "size": len(data),
            "magic": data[:4].decode(
                "ascii",
                errors="replace",
            ),
            "original_sha256": sha256(data),
            "secret_region": {
                "start": f"0x{SECRET_START:04x}",
                "end_exclusive": f"0x{SECRET_END:04x}",
                "length": SECRET_END - SECRET_START,
                "sha256": sha256(secret),
            },
        },

        "management": management,

        "ports": {
            "pvid_raw_order": pvids,
        },

        "vlans": vlans,

        "notes": [
            (
                "PVID raw indexes have not yet been mapped "
                "to front-panel port numbers."
            ),
            (
                "VLAN metadata is preserved exactly but "
                "has not yet been interpreted."
            ),
            (
                "The account/credential region is stored "
                "separately as secrets.bin."
            ),
            (
                "template.bin contains the complete original "
                "configuration except that the secret region "
                "has been zeroed."
            ),
            (
                "Do not commit secrets.bin or reconstructed "
                "uploadable .bin files to Git."
            ),
        ],
    }

    config_path = outdir / "config.json"

    config_path.write_text(
        json.dumps(config, indent=2) + "\n"
    )

    print(f"Wrote: {config_path}")
    print(f"Wrote: {template_path}")
    print(
        f"Wrote: {secret_path} "
        "[SENSITIVE - DO NOT COMMIT]"
    )


# ----------------------------------------------------------------------
# Encode
# ----------------------------------------------------------------------

def encode(indir, outfile):
    indir = Path(indir)

    config_path = indir / "config.json"
    template_path = indir / "template.bin"
    secret_path = indir / "secrets.bin"

    if not config_path.exists():
        raise FileNotFoundError(config_path)

    if not template_path.exists():
        raise FileNotFoundError(template_path)

    if not secret_path.exists():
        raise FileNotFoundError(
            f"{secret_path} is required to reconstruct "
            "an uploadable configuration."
        )

    config = json.loads(
        config_path.read_text()
    )

    template = template_path.read_bytes()

    if len(template) != EXPECTED_SIZE:
        raise ValueError(
            "template.bin has unexpected size"
        )

    if template[:4] != MAGIC:
        raise ValueError(
            "template.bin has unexpected magic"
        )

    data = bytearray(template)

    # --------------------------------------------------------------
    # Restore sensitive bytes
    # --------------------------------------------------------------

    secret = secret_path.read_bytes()

    expected_secret_len = SECRET_END - SECRET_START

    if len(secret) != expected_secret_len:
        raise ValueError(
            f"secrets.bin is {len(secret)} bytes; "
            f"expected {expected_secret_len}"
        )

    data[SECRET_START:SECRET_END] = secret

    # --------------------------------------------------------------
    # Management
    # --------------------------------------------------------------

    management = config["management"]

    dhcp = management["dhcp"]

    if not isinstance(dhcp, bool):
        raise ValueError(
            "management.dhcp must be true or false"
        )

    data[DHCP_OFFSET] = 1 if dhcp else 0

    data[
        IP_OFFSET:IP_OFFSET + 4
    ] = ipv4_bytes(
        management["address"]
    )

    data[
        MASK_OFFSET:MASK_OFFSET + 4
    ] = ipv4_bytes(
        management["netmask"]
    )

    data[
        GW_OFFSET:GW_OFFSET + 4
    ] = ipv4_bytes(
        management["gateway"]
    )

    # --------------------------------------------------------------
    # PVIDs
    # --------------------------------------------------------------

    pvid_entries = config[
        "ports"
    ]["pvid_raw_order"]

    if len(pvid_entries) != PVID_COUNT:
        raise ValueError(
            f"Expected {PVID_COUNT} PVID entries; "
            f"got {len(pvid_entries)}"
        )

    for i, entry in enumerate(pvid_entries):
        value = int(entry["pvid"])

        if not 0 <= value <= 4095:
            raise ValueError(
                f"Invalid PVID {value} "
                f"at raw index {i}"
            )

        pos = PVID_OFFSET + i * 2

        data[pos:pos + 2] = value.to_bytes(
            2,
            byteorder="big",
        )

    # --------------------------------------------------------------
    # VLAN records
    # --------------------------------------------------------------

    vlans = config["vlans"]

    if len(vlans) != VLAN_RECORD_COUNT:
        raise ValueError(
            f"Expected {VLAN_RECORD_COUNT} VLAN records; "
            f"got {len(vlans)}"
        )

    for i, vlan in enumerate(vlans):
        pos = VLAN_OFFSET + i * VLAN_RECORD_SIZE

        vid = int(vlan["id"])

        if not 1 <= vid <= 4094:
            raise ValueError(
                f"Invalid VLAN ID {vid}"
            )

        name = vlan["name"].encode("ascii")

        if len(name) > NAME_LEN:
            raise ValueError(
                f"VLAN {vid} name is {len(name)} bytes; "
                f"maximum is {NAME_LEN}"
            )

        metadata = parse_hex_metadata(
            vlan["metadata_hex"]
        )

        # VLAN ID
        data[
            pos + VID_OFFSET:
            pos + VID_OFFSET + 2
        ] = vid.to_bytes(
            2,
            byteorder="big",
        )

        # Fixed-length name
        padded_name = (
            name
            + b"\x00" * (NAME_LEN - len(name))
        )

        data[
            pos + NAME_OFFSET:
            pos + NAME_OFFSET + NAME_LEN
        ] = padded_name

        # Unknown-but-preserved metadata
        data[
            pos + META_OFFSET:
            pos + META_OFFSET + META_LEN
        ] = metadata

    # --------------------------------------------------------------
    # Final validation
    # --------------------------------------------------------------

    if len(data) != EXPECTED_SIZE:
        raise ValueError(
            "Internal error: output size changed"
        )

    if data[:4] != MAGIC:
        raise ValueError(
            "Internal error: output magic changed"
        )

    outfile = Path(outfile)
    outfile.write_bytes(data)

    output_hash = sha256(data)

    print(f"Wrote: {outfile}")
    print(f"Size: {len(data)} bytes")
    print(f"SHA256: {output_hash}")

    expected_hash = config.get(
        "format",
        {},
    ).get(
        "original_sha256"
    )

    if expected_hash:
        if output_hash == expected_hash:
            print(
                "ROUND-TRIP MATCH: output is byte-for-byte "
                "identical to the original backup."
            )
        else:
            print(
                "Output differs from original backup."
            )
            print(
                "This is expected if config.json was edited."
            )


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Decoder/encoder for HORACO RTL8373 "
            "switch configuration backups"
        )
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    decode_parser = subparsers.add_parser(
        "decode",
        help="Decode a HORACO configuration backup",
    )

    decode_parser.add_argument(
        "bin",
        help="Input switch_cfg.bin",
    )

    decode_parser.add_argument(
        "outdir",
        help="Output directory",
    )

    encode_parser = subparsers.add_parser(
        "encode",
        help="Reconstruct a HORACO configuration backup",
    )

    encode_parser.add_argument(
        "indir",
        help=(
            "Directory containing config.json, "
            "template.bin, and secrets.bin"
        ),
    )

    encode_parser.add_argument(
        "bin",
        help="Output .bin filename",
    )

    args = parser.parse_args()

    if args.command == "decode":
        decode(
            args.bin,
            args.outdir,
        )

    elif args.command == "encode":
        encode(
            args.indir,
            args.bin,
        )


if __name__ == "__main__":
    main()