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


# ============================================================================
# Management configuration
# ============================================================================

DHCP_OFFSET = 0x04
IP_OFFSET = 0x05
MASK_OFFSET = 0x09
GW_OFFSET = 0x0D


# ============================================================================
# Sensitive account / credential region
# ============================================================================

SECRET_START = 0x17
SECRET_END = 0x4D


# ============================================================================
# Physical port VLAN configuration
# ============================================================================
#
# Nine physical front-panel ports, ports 1..9.
#
# PVID:
#   nine uint16 big-endian values beginning at 0x04CC
#
# Accepted Frame Type:
#   nine uint8 values beginning at 0x04E4
#
# Verified by controlled Port 6 experiments:
#
#   0 = All
#   1 = Tagged
#   2 = Untagged
# ============================================================================

PORT_COUNT = 9

PVID_OFFSET = 0x4CC

ACCEPTED_FRAME_OFFSET = 0x4E4

ACCEPTED_FRAME_TYPES = {
    0: "all",
    1: "tagged",
    2: "untagged",
}

ACCEPTED_FRAME_VALUES = {
    name: value
    for value, name in ACCEPTED_FRAME_TYPES.items()
}


# ============================================================================
# VLAN configuration header / slot index
# ============================================================================
#
# Two uint16 fields at 0x0530 and 0x0532 remain unidentified.
#
# Both have consistently contained 1 across every observed configuration:
# factory-ish configuration, static configuration, DHCP configuration,
# VLAN edits, VLAN creation, and VLAN deletion.
#
# Following those words is a verified 31-entry VLAN VID slot index:
#
#   0x0534 slot 0
#   ...
#   0x0570 slot 30
#
# 0xFFFF represents an unused slot.
#
# A controlled creation of VLAN 123 populated slot 7 at 0x0542 and created
# the matching VLAN record at 0x0644.
# ============================================================================

UNKNOWN_VLAN_HEADER_OFFSET = 0x530
UNKNOWN_VLAN_HEADER_COUNT = 2

VLAN_INDEX_OFFSET = 0x534
VLAN_SLOT_COUNT = 31
VLAN_UNUSED = 0xFFFF


# ============================================================================
# VLAN records
# ============================================================================
#
# 31 records, 26 bytes each:
#
#   slot 0  = 0x058E
#   ...
#   slot 30 = 0x089A
#
# The next 26-byte stride (0x08B4) is NOT a VLAN record.
#
# Record layout:
#
#   +0x00  uint16 BE   VLAN ID
#   +0x02  char[16]    VLAN name, NUL padded
#   +0x12  uint32 BE   member metadata word
#   +0x16  uint32 BE   tagged metadata word
#
# Verified by controlled changes:
#
#   bits 8..16 of member word = physical member ports 1..9
#   bits 8..16 of tagged word = physical tagged ports 1..9
#
# Other bits remain unidentified and are preserved during encoding.
# ============================================================================

VLAN_OFFSET = 0x58E
VLAN_RECORD_SIZE = 26

VID_OFFSET = 0
NAME_OFFSET = 2
NAME_LEN = 16
META_OFFSET = 18
META_LEN = 8

VLAN_PORT_MASK = 0x1FF
VLAN_PORT_WORD_MASK = VLAN_PORT_MASK << 8


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


def ports_from_mask(mask):
    return [
        port
        for port in range(1, PORT_COUNT + 1)
        if mask & (1 << (port - 1))
    ]


def mask_from_ports(ports, field_name):
    if not isinstance(ports, list):
        raise ValueError(
            f"{field_name} must be a JSON list"
        )

    mask = 0
    seen = set()

    for raw_port in ports:
        if isinstance(raw_port, bool):
            raise ValueError(
                f"{field_name} contains invalid port "
                f"{raw_port!r}"
            )

        try:
            port = int(raw_port)

        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{field_name} contains invalid port "
                f"{raw_port!r}"
            ) from exc

        if not 1 <= port <= PORT_COUNT:
            raise ValueError(
                f"{field_name} port {port} "
                f"is outside range 1..{PORT_COUNT}"
            )

        if port in seen:
            raise ValueError(
                f"{field_name} contains duplicate "
                f"port {port}"
            )

        seen.add(port)

        mask |= (
            1 << (port - 1)
        )

    return mask


def parse_word(value, field_name):
    if isinstance(value, bool):
        raise ValueError(
            f"{field_name} must not be boolean"
        )

    if isinstance(value, int):
        word = value

    elif isinstance(value, str):
        try:
            word = int(value, 0)

        except ValueError as exc:
            raise ValueError(
                f"Invalid {field_name}: "
                f"{value!r}"
            ) from exc

    else:
        raise ValueError(
            f"{field_name} must be an integer "
            "or 0x-prefixed string"
        )

    if not 0 <= word <= 0xFFFFFFFF:
        raise ValueError(
            f"{field_name} is outside uint32 range"
        )

    return word


def vlan_record_offset(slot):
    return (
        VLAN_OFFSET
        + slot * VLAN_RECORD_SIZE
    )


def vlan_index_offset(slot):
    return (
        VLAN_INDEX_OFFSET
        + slot * 2
    )


# ============================================================================
# VLAN record decoding
# ============================================================================

def decode_vlan_record(data, slot):
    pos = vlan_record_offset(slot)

    rec = data[
        pos:
        pos + VLAN_RECORD_SIZE
    ]

    if len(rec) != VLAN_RECORD_SIZE:
        raise ValueError(
            f"VLAN slot {slot} record is incomplete "
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
        "slot":
            slot,

        "offset":
            f"0x{pos:04x}",

        "id":
            vid,

        "name":
            name,

        "members":
            ports_from_mask(
                member_mask
            ),

        "tagged":
            ports_from_mask(
                tagged_mask
            ),

        "untagged":
            ports_from_mask(
                untagged_mask
            ),

        "metadata_preserved": {
            "member_word":
                f"0x{member_word:08x}",

            "tagged_word":
                f"0x{tagged_word:08x}",
        },

        "raw_hex":
            rec.hex(),
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

    template = bytearray(
        data
    )

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
    # Port configuration
    # ------------------------------------------------------------------------

    ports = []

    for i in range(PORT_COUNT):
        port = i + 1

        pvid_pos = (
            PVID_OFFSET
            + i * 2
        )

        pvid = int.from_bytes(
            data[
                pvid_pos:
                pvid_pos + 2
            ],
            byteorder="big",
        )

        frame_pos = (
            ACCEPTED_FRAME_OFFSET
            + i
        )

        frame_raw = (
            data[frame_pos]
        )

        frame_name = (
            ACCEPTED_FRAME_TYPES
            .get(
                frame_raw,
                f"unknown-{frame_raw}",
            )
        )

        ports.append({
            "port":
                port,

            "pvid":
                pvid,

            "pvid_offset":
                f"0x{pvid_pos:04x}",

            "accepted_frame_type":
                frame_name,

            "accepted_frame_type_raw":
                frame_raw,

            "accepted_frame_type_offset":
                f"0x{frame_pos:04x}",
        })


    # ------------------------------------------------------------------------
    # Unknown VLAN header words
    # ------------------------------------------------------------------------

    vlan_header_words = []

    for i in range(
        UNKNOWN_VLAN_HEADER_COUNT
    ):
        pos = (
            UNKNOWN_VLAN_HEADER_OFFSET
            + i * 2
        )

        value = int.from_bytes(
            data[
                pos:
                pos + 2
            ],
            byteorder="big",
        )

        vlan_header_words.append({
            "index":
                i,

            "offset":
                f"0x{pos:04x}",

            "value":
                value,
        })


    # ------------------------------------------------------------------------
    # VLAN index and records
    # ------------------------------------------------------------------------

    vlan_slots = []
    vlans = []

    seen_vids = set()

    for slot in range(
        VLAN_SLOT_COUNT
    ):
        index_pos = (
            vlan_index_offset(slot)
        )

        indexed_vid = int.from_bytes(
            data[
                index_pos:
                index_pos + 2
            ],
            byteorder="big",
        )

        record = decode_vlan_record(
            data,
            slot,
        )

        record_vid = (
            record["id"]
        )

        record_is_zero = (
            data[
                vlan_record_offset(slot):
                vlan_record_offset(slot)
                + VLAN_RECORD_SIZE
            ]
            == b"\x00" * VLAN_RECORD_SIZE
        )

        if indexed_vid == VLAN_UNUSED:
            state = "unused"

            if not record_is_zero:
                raise ValueError(
                    f"VLAN slot {slot}: "
                    "index is unused (0xFFFF), "
                    "but record is not zero"
                )

        else:
            state = "populated"

            if record_vid != indexed_vid:
                raise ValueError(
                    f"VLAN slot {slot}: "
                    f"index VID {indexed_vid} "
                    f"does not match record VID "
                    f"{record_vid}"
                )

            if indexed_vid in seen_vids:
                raise ValueError(
                    f"Duplicate VLAN ID "
                    f"{indexed_vid}"
                )

            if not 1 <= indexed_vid <= 4094:
                raise ValueError(
                    f"VLAN slot {slot}: "
                    f"invalid VID {indexed_vid}"
                )

            seen_vids.add(
                indexed_vid
            )

            vlans.append(
                record
            )

        vlan_slots.append({
            "slot":
                slot,

            "index_offset":
                f"0x{index_pos:04x}",

            "record_offset":
                (
                    f"0x"
                    f"{vlan_record_offset(slot):04x}"
                ),

            "state":
                state,

            "indexed_vid":
                indexed_vid,
        })


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

        "ports":
            ports,

        "vlan_storage": {
            "slot_count":
                VLAN_SLOT_COUNT,

            "unused_index_value":
                "0xffff",

            "unknown_header_words":
                vlan_header_words,

            "slots":
                vlan_slots,
        },

        "vlans":
            vlans,

        "notes": [
            (
                "Tested on HORACO "
                "ZX-AFGW-SWTG218ANS-150, "
                "hardware V1.0, firmware V100.9.9."
            ),

            (
                "Physical-port PVIDs are nine "
                "sequential uint16 big-endian values "
                "beginning at 0x04CC."
            ),

            (
                "Accepted Frame Type is stored as "
                "nine sequential bytes beginning at "
                "0x04E4: 0=all, 1=tagged, "
                "2=untagged."
            ),

            (
                "The words at 0x0530 and 0x0532 "
                "remain unidentified."
            ),

            (
                "VLAN storage contains 31 indexed "
                "slots. The VID index begins at "
                "0x0534 and VLAN records begin "
                "at 0x058E."
            ),

            (
                "0xFFFF marks an unused VLAN "
                "index slot; corresponding unused "
                "records have been observed as "
                "all zeroes."
            ),

            (
                "VLAN member and tagged front-panel "
                "port masks occupy bits 8..16 of "
                "two preserved uint32 metadata words."
            ),

            (
                "VLAN untagged ports are derived as "
                "members minus tagged ports."
            ),

            (
                "This encoder edits existing populated "
                "VLAN slots only. It intentionally does "
                "not create or delete VLAN slots."
            ),

            (
                "Unknown binary data is preserved "
                "through template.bin."
            ),

            (
                "Do not commit secrets.bin or "
                "reconstructed uploadable BIN files."
            ),
        ],
    }


    # ------------------------------------------------------------------------
    # Write files
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

    data = bytearray(
        template
    )


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

    dhcp = (
        management["dhcp"]
    )

    if not isinstance(
        dhcp,
        bool,
    ):
        raise ValueError(
            "management.dhcp must be true or false"
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
    # Port configuration
    # ------------------------------------------------------------------------

    ports = (
        config["ports"]
    )

    if len(ports) != PORT_COUNT:
        raise ValueError(
            f"Expected {PORT_COUNT} ports; "
            f"got {len(ports)}"
        )

    seen_ports = set()

    for entry in ports:
        port = int(
            entry["port"]
        )

        if not 1 <= port <= PORT_COUNT:
            raise ValueError(
                f"Invalid port {port}"
            )

        if port in seen_ports:
            raise ValueError(
                f"Duplicate port {port}"
            )

        seen_ports.add(
            port
        )

        i = port - 1

        pvid = int(
            entry["pvid"]
        )

        if not 0 <= pvid <= 4095:
            raise ValueError(
                f"Invalid PVID {pvid} "
                f"for port {port}"
            )

        pvid_pos = (
            PVID_OFFSET
            + i * 2
        )

        data[
            pvid_pos:
            pvid_pos + 2
        ] = pvid.to_bytes(
            2,
            byteorder="big",
        )

        frame_type = (
            entry[
                "accepted_frame_type"
            ]
        )

        if (
            frame_type
            not in ACCEPTED_FRAME_VALUES
        ):
            raise ValueError(
                f"Invalid Accepted Frame Type "
                f"{frame_type!r} for port {port}. "
                "Expected all, tagged, or untagged."
            )

        frame_pos = (
            ACCEPTED_FRAME_OFFSET
            + i
        )

        data[frame_pos] = (
            ACCEPTED_FRAME_VALUES[
                frame_type
            ]
        )


    # ------------------------------------------------------------------------
    # Unknown VLAN header words
    # ------------------------------------------------------------------------
    #
    # These remain unknown. Preserve template bytes and verify that config.json
    # still describes the same values.
    # ------------------------------------------------------------------------

    header_entries = (
        config[
            "vlan_storage"
        ][
            "unknown_header_words"
        ]
    )

    if (
        len(header_entries)
        != UNKNOWN_VLAN_HEADER_COUNT
    ):
        raise ValueError(
            "Unexpected number of "
            "unknown VLAN header words"
        )

    for i, entry in enumerate(
        header_entries
    ):
        pos = (
            UNKNOWN_VLAN_HEADER_OFFSET
            + i * 2
        )

        template_value = int.from_bytes(
            data[
                pos:
                pos + 2
            ],
            byteorder="big",
        )

        json_value = int(
            entry["value"]
        )

        if json_value != template_value:
            raise ValueError(
                f"Unknown VLAN header word "
                f"{i} was edited. "
                "Editing unknown fields is not allowed."
            )


    # ------------------------------------------------------------------------
    # Determine VLAN slots present in original template
    # ------------------------------------------------------------------------

    original_populated_slots = set()

    for slot in range(
        VLAN_SLOT_COUNT
    ):
        pos = (
            vlan_index_offset(slot)
        )

        vid = int.from_bytes(
            data[
                pos:
                pos + 2
            ],
            byteorder="big",
        )

        if vid != VLAN_UNUSED:
            original_populated_slots.add(
                slot
            )


    # ------------------------------------------------------------------------
    # Validate configured VLANs
    # ------------------------------------------------------------------------

    vlans = (
        config["vlans"]
    )

    configured_slots = set()
    configured_vids = set()

    for vlan in vlans:
        slot = int(
            vlan["slot"]
        )

        if not 0 <= slot < VLAN_SLOT_COUNT:
            raise ValueError(
                f"Invalid VLAN slot {slot}"
            )

        if slot in configured_slots:
            raise ValueError(
                f"Duplicate VLAN slot {slot}"
            )

        configured_slots.add(
            slot
        )

        vid = int(
            vlan["id"]
        )

        if not 1 <= vid <= 4094:
            raise ValueError(
                f"Invalid VLAN ID {vid}"
            )

        if vid in configured_vids:
            raise ValueError(
                f"Duplicate VLAN ID {vid}"
            )

        configured_vids.add(
            vid
        )


    # ------------------------------------------------------------------------
    # Creation/deletion intentionally unsupported
    # ------------------------------------------------------------------------

    if (
        configured_slots
        != original_populated_slots
    ):
        missing = sorted(
            original_populated_slots
            - configured_slots
        )

        added = sorted(
            configured_slots
            - original_populated_slots
        )

        raise ValueError(
            "VLAN slot creation/deletion is not "
            "supported yet. "
            f"Missing slots: {missing}; "
            f"new slots: {added}"
        )


    # ------------------------------------------------------------------------
    # Encode existing VLAN records and matching index entries
    # ------------------------------------------------------------------------

    for vlan in vlans:
        slot = int(
            vlan["slot"]
        )

        vid = int(
            vlan["id"]
        )

        pos = (
            vlan_record_offset(slot)
        )

        index_pos = (
            vlan_index_offset(slot)
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

        member_mask = (
            mask_from_ports(
                vlan["members"],
                f"VLAN {vid} members",
            )
        )

        tagged_mask = (
            mask_from_ports(
                vlan["tagged"],
                f"VLAN {vid} tagged",
            )
        )

        invalid_tagged = (
            tagged_mask
            & ~member_mask
        )

        if invalid_tagged:
            raise ValueError(
                f"VLAN {vid}: tagged ports "
                f"{ports_from_mask(invalid_tagged)} "
                "are not VLAN members"
            )

        preserved = (
            vlan[
                "metadata_preserved"
            ]
        )

        member_word = (
            parse_word(
                preserved[
                    "member_word"
                ],
                f"VLAN {vid} member_word",
            )
        )

        tagged_word = (
            parse_word(
                preserved[
                    "tagged_word"
                ],
                f"VLAN {vid} tagged_word",
            )
        )

        # Preserve all unidentified bits.
        member_word &= (
            ~VLAN_PORT_WORD_MASK
            & 0xFFFFFFFF
        )

        member_word |= (
            member_mask << 8
        )

        tagged_word &= (
            ~VLAN_PORT_WORD_MASK
            & 0xFFFFFFFF
        )

        tagged_word |= (
            tagged_mask << 8
        )


        # Update matching VID index.
        data[
            index_pos:
            index_pos + 2
        ] = vid.to_bytes(
            2,
            byteorder="big",
        )


        # Update record VID.
        data[
            pos + VID_OFFSET:
            pos + VID_OFFSET + 2
        ] = vid.to_bytes(
            2,
            byteorder="big",
        )


        # Update record name.
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


        # Update verified member/tagged bits,
        # preserving all other metadata bits.
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


    # ------------------------------------------------------------------------
    # Final consistency check: index vs VLAN records
    # ------------------------------------------------------------------------

    for slot in range(
        VLAN_SLOT_COUNT
    ):
        index_pos = (
            vlan_index_offset(slot)
        )

        record_pos = (
            vlan_record_offset(slot)
        )

        indexed_vid = int.from_bytes(
            data[
                index_pos:
                index_pos + 2
            ],
            byteorder="big",
        )

        record_vid = int.from_bytes(
            data[
                record_pos:
                record_pos + 2
            ],
            byteorder="big",
        )

        record = data[
            record_pos:
            record_pos + VLAN_RECORD_SIZE
        ]

        if indexed_vid == VLAN_UNUSED:
            if record != (
                b"\x00"
                * VLAN_RECORD_SIZE
            ):
                raise ValueError(
                    f"VLAN slot {slot}: "
                    "unused index has nonzero record"
                )

        elif record_vid != indexed_vid:
            raise ValueError(
                f"VLAN slot {slot}: "
                f"index VID {indexed_vid} "
                f"does not match record VID "
                f"{record_vid}"
            )


    # ------------------------------------------------------------------------
    # Structural checks
    # ------------------------------------------------------------------------

    if len(data) != EXPECTED_SIZE:
        raise ValueError(
            "Internal error: output size changed"
        )

    if data[:4] != MAGIC:
        raise ValueError(
            "Internal error: output magic changed"
        )


    # ------------------------------------------------------------------------
    # Write output
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
                "identical to the original backup."
            )

        else:
            print(
                "Output differs from original backup."
            )

            print(
                "This is expected if config.json "
                "was intentionally edited."
            )


# ============================================================================
# CLI
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
        help="Output .bin filename",
    )

    args = (
        parser.parse_args()
    )

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
