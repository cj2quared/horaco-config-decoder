#!/usr/bin/env python3

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path


# ============================================================================
# HORACO configuration backup decoder / encoder
#
# Reverse-engineered from:
#
#   Device:   HORACO ZX-AFGW-SWTG218ANS-150
#   Hardware: V1.0
#   Firmware: V100.9.9
#
# Observed backup size:
#   2667 bytes
#
# Only fields verified against real switch configuration are given semantic
# names. Unknown data is preserved exactly wherever possible.
# ============================================================================


EXPECTED_SIZE = 2667
MAGIC = b"#y#y"

DHCP_OFFSET = 0x04
IP_OFFSET = 0x05
MASK_OFFSET = 0x09
GW_OFFSET = 0x0D

SECRET_START = 0x17
SECRET_END = 0x4D

# Verified physical front-panel PVIDs.
# Nine uint16 big-endian values corresponding to ports 1..9.
PVID_OFFSET = 0x4CC
PVID_COUNT = 9

# Unknown 16-bit table. Do not interpret as PVIDs.
UNKNOWN_VLAN_TABLE_OFFSET = 0x530
UNKNOWN_VLAN_TABLE_COUNT = 9

# Verified VLAN record layout.
VLAN_OFFSET = 0x58E
VLAN_RECORD_SIZE = 26
VLAN_RECORD_COUNT = 7

VID_OFFSET = 0
NAME_OFFSET = 2
NAME_LEN = 16
META_OFFSET = 18
META_LEN = 8

# Verified by controlled VLAN changes:
#
# Each 8-byte VLAN metadata field consists of two BE uint32 words.
# Front-panel port bits 1..9 occupy word bits 8..16.
#
#   metadata[0:4] : member word
#   metadata[4:8] : tagged word
#
# All bits outside this mask remain unidentified and MUST be preserved.
VLAN_PORT_MASK = 0x1FF
VLAN_PORT_WORD_MASK = VLAN_PORT_MASK << 8


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_bin(path):
    path = Path(path)
    data = path.read_bytes()

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


def ports_from_mask(mask):
    return [
        port
        for port in range(1, 10)
        if mask & (1 << (port - 1))
    ]


def mask_from_ports(ports, field_name):
    mask = 0
    seen = set()

    if not isinstance(ports, list):
        raise ValueError(
            f"{field_name} must be a JSON list of port numbers"
        )

    for raw_port in ports:
        if isinstance(raw_port, bool):
            raise ValueError(
                f"{field_name} contains invalid port {raw_port!r}"
            )

        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{field_name} contains invalid port {raw_port!r}"
            ) from exc

        if port < 1 or port > 9:
            raise ValueError(
                f"{field_name} port {port} is outside valid range 1..9"
            )

        if port in seen:
            raise ValueError(
                f"{field_name} contains duplicate port {port}"
            )

        seen.add(port)
        mask |= 1 << (port - 1)

    return mask


def parse_word(value, field_name):
    if isinstance(value, int):
        word = value

    elif isinstance(value, str):
        try:
            word = int(value, 0)
        except ValueError as exc:
            raise ValueError(
                f"Invalid {field_name}: {value!r}"
            ) from exc

    else:
        raise ValueError(
            f"{field_name} must be an integer or 0x-prefixed string"
        )

    if not 0 <= word <= 0xFFFFFFFF:
        raise ValueError(
            f"{field_name} is outside uint32 range: {word}"
        )

    return word


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
        NAME_OFFSET:
        NAME_OFFSET + NAME_LEN
    ]

    name = (
        name_raw
        .split(b"\x00", 1)[0]
        .decode("ascii", errors="replace")
    )

    metadata = rec[
        META_OFFSET:
        META_OFFSET + META_LEN
    ]

    member_word = int.from_bytes(
        metadata[0:4],
        byteorder="big",
    )

    tagged_word = int.from_bytes(
        metadata[4:8],
        byteorder="big",
    )

    member_mask = (
        member_word >> 8
    ) & VLAN_PORT_MASK

    tagged_mask = (
        tagged_word >> 8
    ) & VLAN_PORT_MASK

    untagged_mask = (
        member_mask
        & ~tagged_mask
        & VLAN_PORT_MASK
    )

    return {
        "index": index,
        "offset": f"0x{pos:04x}",
        "id": vid,
        "name": name,

        "members":
            ports_from_mask(member_mask),

        "tagged":
            ports_from_mask(tagged_mask),

        "untagged":
            ports_from_mask(untagged_mask),

        "metadata_preserved": {
            "member_word":
                f"0x{member_word:08x}",

            "tagged_word":
                f"0x{tagged_word:08x}",
        },

        "raw_hex": rec.hex(),
    }


def decode(path, outdir):
    data = load_bin(path)

    outdir = Path(outdir)
    outdir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ------------------------------------------------------------------------
    # Sensitive region
    # ------------------------------------------------------------------------

    secret = data[
        SECRET_START:
        SECRET_END
    ]

    secret_path = (
        outdir / "secrets.bin"
    )

    secret_path.write_bytes(
        secret
    )

    # ------------------------------------------------------------------------
    # Sanitized binary template
    # ------------------------------------------------------------------------

    template = bytearray(data)

    template[
        SECRET_START:
        SECRET_END
    ] = (
        b"\x00"
        * (SECRET_END - SECRET_START)
    )

    template_path = (
        outdir / "template.bin"
    )

    template_path.write_bytes(
        template
    )

    # ------------------------------------------------------------------------
    # Management
    # ------------------------------------------------------------------------

    management = {
        "dhcp_raw":
            data[DHCP_OFFSET],

        "dhcp":
            bool(data[DHCP_OFFSET]),

        "address":
            ipv4(
                data[
                    IP_OFFSET:
                    IP_OFFSET + 4
                ]
            ),

        "netmask":
            ipv4(
                data[
                    MASK_OFFSET:
                    MASK_OFFSET + 4
                ]
            ),

        "gateway":
            ipv4(
                data[
                    GW_OFFSET:
                    GW_OFFSET + 4
                ]
            ),
    }

    # ------------------------------------------------------------------------
    # Port PVIDs
    # ------------------------------------------------------------------------

    pvids = []

    for i in range(PVID_COUNT):
        pos = (
            PVID_OFFSET
            + i * 2
        )

        value = int.from_bytes(
            data[pos:pos + 2],
            byteorder="big",
        )

        pvids.append({
            "port":
                i + 1,

            "offset":
                f"0x{pos:04x}",

            "pvid":
                value,
        })

    # ------------------------------------------------------------------------
    # Unknown VLAN-related table
    # ------------------------------------------------------------------------

    unknown_vlan_id_table = []

    for i in range(
        UNKNOWN_VLAN_TABLE_COUNT
    ):
        pos = (
            UNKNOWN_VLAN_TABLE_OFFSET
            + i * 2
        )

        value = int.from_bytes(
            data[pos:pos + 2],
            byteorder="big",
        )

        unknown_vlan_id_table.append({
            "raw_index":
                i,

            "offset":
                f"0x{pos:04x}",

            "value":
                value,
        })

    # ------------------------------------------------------------------------
    # VLANs
    # ------------------------------------------------------------------------

    vlans = [
        decode_vlan_record(data, i)
        for i in range(VLAN_RECORD_COUNT)
    ]

    config = {
        "device_profile": {
            "manufacturer":
                "HORACO",

            "model":
                "ZX-AFGW-SWTG218ANS-150",

            "tested_hardware":
                "V1.0",

            "tested_firmware":
                "V100.9.9",

            "status":
                "experimental reverse-engineered format",
        },

        "format": {
            "size":
                len(data),

            "magic":
                data[:4].decode(
                    "ascii",
                    errors="replace",
                ),

            "original_sha256":
                sha256(data),

            "secret_region": {
                "start":
                    f"0x{SECRET_START:04x}",

                "end_exclusive":
                    f"0x{SECRET_END:04x}",

                "length":
                    SECRET_END - SECRET_START,

                "sha256":
                    sha256(secret),
            },
        },

        "management":
            management,

        "ports": {
            "pvid":
                pvids,
        },

        "unknown": {
            "vlan_id_table":
                unknown_vlan_id_table,
        },

        "vlans":
            vlans,

        "notes": [
            (
                "Tested on HORACO ZX-AFGW-SWTG218ANS-150, "
                "hardware V1.0, firmware V100.9.9."
            ),

            (
                "Other hardware or firmware revisions may "
                "use different configuration layouts."
            ),

            (
                "Physical-port PVIDs are nine sequential "
                "uint16 big-endian values beginning at 0x04CC."
            ),

            (
                "The 16-bit table beginning at 0x0530 remains "
                "unidentified."
            ),

            (
                "VLAN member and tagged port masks occupy "
                "bits 8..16 of two preserved uint32 metadata words."
            ),

            (
                "VLAN untagged ports are derived as "
                "members minus tagged ports."
            ),

            (
                "Unknown bits of both VLAN metadata words are "
                "preserved during encoding."
            ),

            (
                "The account/credential region is stored "
                "separately as secrets.bin."
            ),

            (
                "Do not commit secrets.bin or reconstructed "
                "uploadable configuration BIN files."
            ),
        ],
    }

    config_path = (
        outdir / "config.json"
    )

    config_path.write_text(
        json.dumps(
            config,
            indent=2,
        )
        + "\n"
    )

    print(
        f"Wrote: {config_path}"
    )

    print(
        f"Wrote: {template_path}"
    )

    print(
        f"Wrote: {secret_path} "
        "[SENSITIVE - DO NOT COMMIT]"
    )


def encode(indir, outfile):
    indir = Path(indir)

    config_path = (
        indir / "config.json"
    )

    template_path = (
        indir / "template.bin"
    )

    secret_path = (
        indir / "secrets.bin"
    )

    if not config_path.exists():
        raise FileNotFoundError(
            config_path
        )

    if not template_path.exists():
        raise FileNotFoundError(
            template_path
        )

    if not secret_path.exists():
        raise FileNotFoundError(
            f"{secret_path} is required "
            "to reconstruct an uploadable configuration."
        )

    config = json.loads(
        config_path.read_text()
    )

    template = (
        template_path.read_bytes()
    )

    if len(template) != EXPECTED_SIZE:
        raise ValueError(
            "template.bin has unexpected size"
        )

    if template[:4] != MAGIC:
        raise ValueError(
            "template.bin has unexpected magic"
        )

    data = bytearray(template)

    # ------------------------------------------------------------------------
    # Restore sensitive region
    # ------------------------------------------------------------------------

    secret = (
        secret_path.read_bytes()
    )

    expected_secret_len = (
        SECRET_END
        - SECRET_START
    )

    if len(secret) != expected_secret_len:
        raise ValueError(
            f"secrets.bin is {len(secret)} bytes; "
            f"expected {expected_secret_len}"
        )

    data[
        SECRET_START:
        SECRET_END
    ] = secret

    # ------------------------------------------------------------------------
    # Management
    # ------------------------------------------------------------------------

    management = (
        config["management"]
    )

    dhcp = management["dhcp"]

    if not isinstance(dhcp, bool):
        raise ValueError(
            "management.dhcp must be true or false"
        )

    data[DHCP_OFFSET] = (
        1 if dhcp else 0
    )

    data[
        IP_OFFSET:
        IP_OFFSET + 4
    ] = ipv4_bytes(
        management["address"]
    )

    data[
        MASK_OFFSET:
        MASK_OFFSET + 4
    ] = ipv4_bytes(
        management["netmask"]
    )

    data[
        GW_OFFSET:
        GW_OFFSET + 4
    ] = ipv4_bytes(
        management["gateway"]
    )

    # ------------------------------------------------------------------------
    # Physical port PVIDs
    # ------------------------------------------------------------------------

    pvids = (
        config[
            "ports"
        ][
            "pvid"
        ]
    )

    if len(pvids) != PVID_COUNT:
        raise ValueError(
            f"Expected {PVID_COUNT} port PVID entries; "
            f"got {len(pvids)}"
        )

    for i, entry in enumerate(
        pvids
    ):
        value = int(
            entry["pvid"]
        )

        if not 0 <= value <= 4095:
            raise ValueError(
                f"Invalid PVID {value} "
                f"for port {i + 1}"
            )

        pos = (
            PVID_OFFSET
            + i * 2
        )

        data[
            pos:
            pos + 2
        ] = value.to_bytes(
            2,
            byteorder="big",
        )

    # ------------------------------------------------------------------------
    # Unknown VLAN-related table
    # ------------------------------------------------------------------------

    entries = (
        config[
            "unknown"
        ][
            "vlan_id_table"
        ]
    )

    if (
        len(entries)
        != UNKNOWN_VLAN_TABLE_COUNT
    ):
        raise ValueError(
            f"Expected {UNKNOWN_VLAN_TABLE_COUNT} "
            f"unknown table entries; "
            f"got {len(entries)}"
        )

    for i, entry in enumerate(
        entries
    ):
        value = int(
            entry["value"]
        )

        if not 0 <= value <= 0xFFFF:
            raise ValueError(
                f"Invalid 16-bit value "
                f"{value} at raw index {i}"
            )

        pos = (
            UNKNOWN_VLAN_TABLE_OFFSET
            + i * 2
        )

        data[
            pos:
            pos + 2
        ] = value.to_bytes(
            2,
            byteorder="big",
        )

    # ------------------------------------------------------------------------
    # VLAN records
    # ------------------------------------------------------------------------

    vlans = config["vlans"]

    if len(vlans) != VLAN_RECORD_COUNT:
        raise ValueError(
            f"Expected {VLAN_RECORD_COUNT} VLAN records; "
            f"got {len(vlans)}"
        )

    for i, vlan in enumerate(
        vlans
    ):
        pos = (
            VLAN_OFFSET
            + i * VLAN_RECORD_SIZE
        )

        vid = int(
            vlan["id"]
        )

        if not 0 <= vid <= 4094:
            raise ValueError(
                f"Invalid VLAN ID {vid}"
            )

        name = (
            vlan["name"]
            .encode("ascii")
        )

        if len(name) > NAME_LEN:
            raise ValueError(
                f"VLAN {vid} name is "
                f"{len(name)} bytes; "
                f"maximum is {NAME_LEN}"
            )

        member_mask = mask_from_ports(
            vlan["members"],
            f"VLAN {vid} members",
        )

        tagged_mask = mask_from_ports(
            vlan["tagged"],
            f"VLAN {vid} tagged",
        )

        if tagged_mask & ~member_mask:
            invalid = ports_from_mask(
                tagged_mask
                & ~member_mask
            )

            raise ValueError(
                f"VLAN {vid}: tagged ports "
                f"{invalid} are not members"
            )

        preserved = (
            vlan[
                "metadata_preserved"
            ]
        )

        member_word = parse_word(
            preserved[
                "member_word"
            ],
            f"VLAN {vid} member_word",
        )

        tagged_word = parse_word(
            preserved[
                "tagged_word"
            ],
            f"VLAN {vid} tagged_word",
        )

        # Preserve every unidentified bit.
        # Modify ONLY verified front-panel-mask bits 8..16.
        member_word = (
            member_word
            & ~VLAN_PORT_WORD_MASK
        )

        member_word |= (
            member_mask << 8
        )

        tagged_word = (
            tagged_word
            & ~VLAN_PORT_WORD_MASK
        )

        tagged_word |= (
            tagged_mask << 8
        )

        # Write VLAN ID.
        data[
            pos + VID_OFFSET:
            pos + VID_OFFSET + 2
        ] = vid.to_bytes(
            2,
            byteorder="big",
        )

        # Write fixed-width VLAN name.
        padded_name = (
            name
            + b"\x00"
            * (
                NAME_LEN
                - len(name)
            )
        )

        data[
            pos + NAME_OFFSET:
            pos + NAME_OFFSET + NAME_LEN
        ] = padded_name

        # Write updated words while preserving unknown bits.
        data[
            pos + META_OFFSET:
            pos + META_OFFSET + 4
        ] = member_word.to_bytes(
            4,
            byteorder="big",
        )

        data[
            pos + META_OFFSET + 4:
            pos + META_OFFSET + 8
        ] = tagged_word.to_bytes(
            4,
            byteorder="big",
        )

    if len(data) != EXPECTED_SIZE:
        raise ValueError(
            "Internal error: output size changed"
        )

    if data[:4] != MAGIC:
        raise ValueError(
            "Internal error: output magic changed"
        )

    outfile = Path(outfile)

    outfile.write_bytes(
        data
    )

    output_hash = sha256(data)

    print(
        f"Wrote: {outfile}"
    )

    print(
        f"Size: {len(data)} bytes"
    )

    print(
        f"SHA256: {output_hash}"
    )

    expected_hash = (
        config
        .get("format", {})
        .get("original_sha256")
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


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Experimental decoder/encoder for "
            "HORACO ZX-AFGW-SWTG218ANS-150 "
            "configuration backups "
            "(tested on HW V1.0 / FW V100.9.9)"
        )
    )

    subparsers = (
        parser.add_subparsers(
            dest="command",
            required=True,
        )
    )

    decode_parser = (
        subparsers.add_parser(
            "decode",
            help=(
                "Decode a HORACO configuration backup"
            ),
        )
    )

    decode_parser.add_argument(
        "bin",
        help="Input switch_cfg.bin",
    )

    decode_parser.add_argument(
        "outdir",
        help="Output directory",
    )

    encode_parser = (
        subparsers.add_parser(
            "encode",
            help=(
                "Reconstruct a HORACO configuration backup"
            ),
        )
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
