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
# Observed configuration backup size:
#   2667 bytes
#
# IMPORTANT:
# Other HORACO models, hardware revisions, and firmware revisions may use
# different layouts.
#
# Only fields that have been reasonably verified are given semantic names.
# Unknown structures are deliberately preserved without guessing their meaning.
# ============================================================================


EXPECTED_SIZE = 2667
MAGIC = b"#y#y"


# ============================================================================
# Known management configuration
# ============================================================================

# Byte 0x04:
#   Observed 0 = DHCP disabled
#   Observed 1 = DHCP enabled
DHCP_OFFSET = 0x04

# IPv4 fields
IP_OFFSET = 0x05
MASK_OFFSET = 0x09
GW_OFFSET = 0x0D


# ============================================================================
# Sensitive account / credential area
# ============================================================================
#
# This region contains account-related data and should be considered sensitive.
#
# The decoder does NOT expose it in config.json.
#
# Instead:
#
#   secrets.bin
#       contains the original bytes
#       DO NOT COMMIT
#
#   template.bin
#       contains the full configuration with this region replaced by zeroes
#
# The encoder re-inserts secrets.bin during reconstruction.
# ============================================================================

SECRET_START = 0x17
SECRET_END = 0x4D  # exclusive


# ============================================================================
# Unknown VLAN-related table
# ============================================================================
#
# Earlier versions of this decoder incorrectly identified this structure as
# the physical-port PVID table.
#
# That interpretation has been disproven by comparison with the switch WebUI.
#
# On one observed configuration this table contains:
#
#   1, 1, 60, 11, 70, 50, 40, 80, 14
#
# Those values correlate strongly with configured VLAN IDs, but the exact
# purpose and semantics of the table remain unknown.
#
# IMPORTANT:
# Values of 0xFFFF have been observed in unused entries, so these must be
# treated as generic unsigned 16-bit values rather than VLAN IDs.
# ============================================================================

UNKNOWN_VLAN_TABLE_OFFSET = 0x530
UNKNOWN_VLAN_TABLE_COUNT = 9


# ============================================================================
# VLAN records
# ============================================================================
#
# Verified record geometry:
#
#   record size: 26 bytes
#
#   +0x00  uint16 BE   VLAN ID
#   +0x02  char[16]    VLAN name, NUL padded
#   +0x12  byte[8]     unknown metadata
#
# Known example:
#
#   VLAN 60 CAMERA
#
#   00 3c
#   43 41 4d 45 52 41 00 00 00 00 00 00 00 00 00 00
#   00 01 df 00 00 01 c0 01
#
# The final 8 bytes appear related to VLAN configuration, but are intentionally
# left uninterpreted until their semantics can be verified.
# ============================================================================

VLAN_OFFSET = 0x58E
VLAN_RECORD_SIZE = 26
VLAN_RECORD_COUNT = 7

VID_OFFSET = 0
NAME_OFFSET = 2
NAME_LEN = 16
META_OFFSET = 18
META_LEN = 8


# ============================================================================
# Utility functions
# ============================================================================

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
    return str(
        ipaddress.IPv4Address(
            bytes(raw)
        )
    )


def ipv4_bytes(address):
    return ipaddress.IPv4Address(
        address
    ).packed


def parse_hex_metadata(value):
    try:
        raw = bytes.fromhex(value)

    except ValueError as exc:
        raise ValueError(
            f"Invalid metadata_hex value: {value!r}"
        ) from exc

    if len(raw) != META_LEN:
        raise ValueError(
            f"VLAN metadata must be exactly "
            f"{META_LEN} bytes; got {len(raw)}"
        )

    return raw


# ============================================================================
# VLAN decoding
# ============================================================================

def decode_vlan_record(data, index):
    pos = (
        VLAN_OFFSET
        + index * VLAN_RECORD_SIZE
    )

    rec = data[
        pos:pos + VLAN_RECORD_SIZE
    ]

    if len(rec) != VLAN_RECORD_SIZE:
        raise ValueError(
            f"VLAN record {index} is incomplete "
            f"at offset 0x{pos:04x}"
        )

    vid = int.from_bytes(
        rec[
            VID_OFFSET:
            VID_OFFSET + 2
        ],
        byteorder="big",
    )

    name_raw = rec[
        NAME_OFFSET:
        NAME_OFFSET + NAME_LEN
    ]

    name = (
        name_raw
        .split(b"\x00", 1)[0]
        .decode(
            "ascii",
            errors="replace",
        )
    )

    metadata = rec[
        META_OFFSET:
        META_OFFSET + META_LEN
    ]

    return {
        "index": index,
        "offset": f"0x{pos:04x}",
        "id": vid,
        "name": name,
        "metadata_hex": metadata.hex(),
        "raw_hex": rec.hex(),
    }


# ============================================================================
# Decode
# ============================================================================

def decode(path, outdir):
    data = load_bin(path)

    outdir = Path(outdir)

    outdir.mkdir(
        parents=True,
        exist_ok=True,
    )


    # ------------------------------------------------------------------------
    # Sensitive account region
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
    #
    # Everything is preserved byte-for-byte except the sensitive account
    # region, which is zeroed.
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
    # Management configuration
    # ------------------------------------------------------------------------

    management = {
        "dhcp_raw":
            data[DHCP_OFFSET],

        "dhcp":
            bool(
                data[DHCP_OFFSET]
            ),

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
    # Unknown VLAN-related 16-bit table
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
            "raw_index": i,
            "offset": f"0x{pos:04x}",
            "value": value,
        })


    # ------------------------------------------------------------------------
    # VLAN records
    # ------------------------------------------------------------------------

    vlans = []

    for i in range(
        VLAN_RECORD_COUNT
    ):
        vlans.append(
            decode_vlan_record(
                data,
                i,
            )
        )


    # ------------------------------------------------------------------------
    # Human-readable configuration
    # ------------------------------------------------------------------------

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

        "unknown": {
            "vlan_id_table":
                unknown_vlan_id_table,
        },

        "vlans":
            vlans,

        "notes": [
            (
                "This format has been tested on a HORACO "
                "ZX-AFGW-SWTG218ANS-150, hardware V1.0, "
                "firmware V100.9.9."
            ),

            (
                "Other hardware and firmware revisions may "
                "use different configuration layouts."
            ),

            (
                "The 16-bit table beginning at 0x0530 was "
                "previously misidentified as the physical-port "
                "PVID table. Its meaning is currently unknown."
            ),

            (
                "The switch WebUI reports physical port PVIDs "
                "independently of the values found in the "
                "0x0530 table."
            ),

            (
                "VLAN metadata is preserved exactly but has "
                "not yet been interpreted."
            ),

            (
                "The account/credential region is stored "
                "separately as secrets.bin."
            ),

            (
                "template.bin contains the complete original "
                "configuration except that the sensitive "
                "account region has been zeroed."
            ),

            (
                "Do not commit secrets.bin or reconstructed "
                "uploadable configuration .bin files to Git."
            ),
        ],
    }


    # ------------------------------------------------------------------------
    # Write readable configuration
    # ------------------------------------------------------------------------

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


    # ------------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------------

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


# ============================================================================
# Encode
# ============================================================================

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


    # ------------------------------------------------------------------------
    # Required files
    # ------------------------------------------------------------------------

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
            "to reconstruct an uploadable "
            "configuration."
        )


    # ------------------------------------------------------------------------
    # Load representation
    # ------------------------------------------------------------------------

    config = json.loads(
        config_path.read_text()
    )

    template = (
        template_path.read_bytes()
    )


    # ------------------------------------------------------------------------
    # Validate template
    # ------------------------------------------------------------------------

    if len(template) != EXPECTED_SIZE:
        raise ValueError(
            "template.bin has "
            "unexpected size"
        )

    if template[:4] != MAGIC:
        raise ValueError(
            "template.bin has "
            "unexpected magic"
        )


    data = bytearray(
        template
    )


    # ------------------------------------------------------------------------
    # Restore sensitive bytes
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
            f"secrets.bin is "
            f"{len(secret)} bytes; "
            f"expected "
            f"{expected_secret_len}"
        )

    data[
        SECRET_START:
        SECRET_END
    ] = secret


    # ------------------------------------------------------------------------
    # Management configuration
    # ------------------------------------------------------------------------

    management = (
        config["management"]
    )

    dhcp = management["dhcp"]

    if not isinstance(
        dhcp,
        bool,
    ):
        raise ValueError(
            "management.dhcp must "
            "be true or false"
        )

    data[DHCP_OFFSET] = (
        1
        if dhcp
        else 0
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
            f"Expected "
            f"{UNKNOWN_VLAN_TABLE_COUNT} "
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
                f"{value} at raw "
                f"index {i}"
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

    vlans = (
        config["vlans"]
    )

    if len(vlans) != VLAN_RECORD_COUNT:
        raise ValueError(
            f"Expected "
            f"{VLAN_RECORD_COUNT} "
            f"VLAN records; "
            f"got {len(vlans)}"
        )


    for i, vlan in enumerate(
        vlans
    ):
        pos = (
            VLAN_OFFSET
            + i * VLAN_RECORD_SIZE
        )


        # --------------------------------------------------------------------
        # VLAN ID
        # --------------------------------------------------------------------

        vid = int(
            vlan["id"]
        )

        if not 0 <= vid <= 4094:
            raise ValueError(
                f"Invalid VLAN ID {vid}"
            )


        # --------------------------------------------------------------------
        # VLAN name
        # --------------------------------------------------------------------

        name = (
            vlan["name"]
            .encode("ascii")
        )

        if len(name) > NAME_LEN:
            raise ValueError(
                f"VLAN {vid} name "
                f"is {len(name)} bytes; "
                f"maximum is {NAME_LEN}"
            )


        # --------------------------------------------------------------------
        # Unknown metadata
        # --------------------------------------------------------------------

        metadata = (
            parse_hex_metadata(
                vlan[
                    "metadata_hex"
                ]
            )
        )


        # --------------------------------------------------------------------
        # Write VLAN ID
        # --------------------------------------------------------------------

        data[
            pos + VID_OFFSET:
            pos + VID_OFFSET + 2
        ] = vid.to_bytes(
            2,
            byteorder="big",
        )


        # --------------------------------------------------------------------
        # Write VLAN name
        # --------------------------------------------------------------------

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


        # --------------------------------------------------------------------
        # Preserve VLAN metadata
        # --------------------------------------------------------------------

        data[
            pos + META_OFFSET:
            pos + META_OFFSET + META_LEN
        ] = metadata


    # ------------------------------------------------------------------------
    # Final structural validation
    # ------------------------------------------------------------------------

    if len(data) != EXPECTED_SIZE:
        raise ValueError(
            "Internal error: "
            "output size changed"
        )

    if data[:4] != MAGIC:
        raise ValueError(
            "Internal error: "
            "output magic changed"
        )


    # ------------------------------------------------------------------------
    # Write reconstructed configuration
    # ------------------------------------------------------------------------

    outfile = Path(outfile)

    outfile.write_bytes(
        data
    )

    output_hash = (
        sha256(data)
    )


    print(
        f"Wrote: {outfile}"
    )

    print(
        f"Size: {len(data)} bytes"
    )

    print(
        f"SHA256: {output_hash}"
    )


    # ------------------------------------------------------------------------
    # Compare against original hash when available
    # ------------------------------------------------------------------------

    expected_hash = (
        config
        .get(
            "format",
            {},
        )
        .get(
            "original_sha256"
        )
    )

    if expected_hash:

        if output_hash == expected_hash:

            print(
                "ROUND-TRIP MATCH: "
                "output is byte-for-byte "
                "identical to the original "
                "backup."
            )

        else:

            print(
                "Output differs from "
                "original backup."
            )

            print(
                "This is expected if "
                "config.json was edited."
            )


# ============================================================================
# Main
# ============================================================================

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


    # ------------------------------------------------------------------------
    # Decode command
    # ------------------------------------------------------------------------

    decode_parser = (
        subparsers.add_parser(
            "decode",
            help=(
                "Decode a HORACO "
                "configuration backup"
            ),
        )
    )

    decode_parser.add_argument(
        "bin",
        help=(
            "Input switch_cfg.bin"
        ),
    )

    decode_parser.add_argument(
        "outdir",
        help=(
            "Output directory"
        ),
    )


    # ------------------------------------------------------------------------
    # Encode command
    # ------------------------------------------------------------------------

    encode_parser = (
        subparsers.add_parser(
            "encode",
            help=(
                "Reconstruct a HORACO "
                "configuration backup"
            ),
        )
    )

    encode_parser.add_argument(
        "indir",
        help=(
            "Directory containing "
            "config.json, template.bin, "
            "and secrets.bin"
        ),
    )

    encode_parser.add_argument(
        "bin",
        help=(
            "Output .bin filename"
        ),
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
