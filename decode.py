import argparse
import binascii
import json
import re
import struct
from typing import Any


DEFAULT_INPUT = (
    "steam://run/730//+csgo_econ_action_preview%204050ADEED1DDF741587D60B04868447044788EECA8B24300934222454840508069224548425080692245484350E66F284E304423C2267B"
)
HEX_PAYLOAD_PATTERN = r"csgo_econ_action_preview(?:%20| )([0-9A-Fa-f]+)$"
MIN_DECODE_SCORE = 5

STICKER_VARINT_FIELDS = {
    1: "slot",
    2: "sticker_id",
    6: "tint_id",
    10: "pattern",
    11: "highlight_reel",
    12: "wrapped_sticker",
}

STICKER_FIXED32_FIELDS = {
    3: "wear",
    4: "scale",
    5: "rotation",
    7: "offset_x",
    8: "offset_y",
    9: "offset_z",
}

ITEM_VARINT_FIELDS = {
    1: "accountid",
    2: "itemid",
    3: "defindex",
    4: "paintindex",
    5: "rarity",
    6: "quality",
    8: "paintseed",
    9: "killeaterscoretype",
    10: "killeatervalue",
    13: "inventory",
    14: "origin",
    15: "questid",
    16: "dropreason",
    17: "musicindex",
    19: "petindex",
    21: "style",
    23: "upgrade_level",
}

ITEM_STICKER_LIST_FIELDS = {
    12: "stickers",
    20: "keychains",
    22: "variations",
}

SCORED_FIELDS = (
    "itemid",
    "accountid",
    "paintindex",
    "paintseed",
    "quality",
    "rarity",
    "inventory",
    "origin",
    "paintwear",
)


def extract_hex_payload(value: str) -> str:
    match = re.search(HEX_PAYLOAD_PATTERN, value)
    if match:
        return match.group(1).upper()

    cleaned = value.strip()
    if re.fullmatch(r"[0-9A-Fa-f]+", cleaned):
        return cleaned.upper()

    raise ValueError("Input does not contain a masked inspect payload")


def xor_mask(data: bytes, key: int) -> bytes:
    return bytes(byte ^ key for byte in data)


def bytes_to_float_bits(value: int) -> float:
    return struct.unpack(">f", struct.pack(">I", value & 0xFFFFFFFF))[0]


def zigzag_decode(value: int) -> int:
    return (value >> 1) ^ -(value & 1)


def read_varint(buffer: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0

    while True:
        if offset >= len(buffer):
            raise ValueError("Unexpected end of buffer while reading varint")

        byte = buffer[offset]
        offset += 1
        result |= (byte & 0x7F) << shift

        if not (byte & 0x80):
            return result, offset

        shift += 7
        if shift > 70:
            raise ValueError("Varint is too long")


def read_fixed32(buffer: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(buffer):
        raise ValueError("Unexpected end of buffer while reading fixed32")
    return struct.unpack("<I", buffer[offset:offset + 4])[0], offset + 4


def fixed32_to_float(value: int) -> float:
    return struct.unpack("<f", struct.pack("<I", value & 0xFFFFFFFF))[0]


def read_length_delimited(buffer: bytes, offset: int) -> tuple[bytes, int]:
    length, offset = read_varint(buffer, offset)
    end = offset + length
    if end > len(buffer):
        raise ValueError("Length-delimited field exceeds buffer")
    return buffer[offset:end], end


def skip_field(buffer: bytes, offset: int, wire_type: int) -> int:
    if wire_type == 0:
        _, offset = read_varint(buffer, offset)
        return offset
    if wire_type == 1:
        end = offset + 8
        if end > len(buffer):
            raise ValueError("Unexpected end of buffer while skipping fixed64")
        return end
    if wire_type == 2:
        _, offset = read_length_delimited(buffer, offset)
        return offset
    if wire_type == 5:
        end = offset + 4
        if end > len(buffer):
            raise ValueError("Unexpected end of buffer while skipping fixed32")
        return end
    raise ValueError(f"Unsupported wire type {wire_type}")


def parse_sticker(buffer: bytes) -> dict[str, Any]:
    sticker: dict[str, Any] = {}
    offset = 0

    while offset < len(buffer):
        tag, offset = read_varint(buffer, offset)
        field_number = tag >> 3
        wire_type = tag & 0x7

        field_name = STICKER_VARINT_FIELDS.get(field_number)
        if field_name is not None:
            value, offset = read_varint(buffer, offset)
            sticker[field_name] = value
            continue

        field_name = STICKER_FIXED32_FIELDS.get(field_number)
        if field_name is not None:
            raw_value, offset = read_fixed32(buffer, offset)
            sticker[field_name] = fixed32_to_float(raw_value)
            continue

        offset = skip_field(buffer, offset, wire_type)

    return sticker


def parse_econ_item(buffer: bytes) -> dict[str, Any]:
    item: dict[str, Any] = {
        "stickers": [],
        "keychains": [],
        "variations": [],
    }
    offset = 0

    while offset < len(buffer):
        tag, offset = read_varint(buffer, offset)
        field_number = tag >> 3
        wire_type = tag & 0x7

        field_name = ITEM_VARINT_FIELDS.get(field_number)
        if field_name is not None:
            value, offset = read_varint(buffer, offset)
            item[field_name] = value
            continue

        if field_number == 7:
            value, offset = read_varint(buffer, offset)
            item["paintwear"] = bytes_to_float_bits(value)
            continue

        if field_number == 11:
            raw, offset = read_length_delimited(buffer, offset)
            item["customname"] = raw.decode("utf-8")
            continue

        sticker_list_name = ITEM_STICKER_LIST_FIELDS.get(field_number)
        if sticker_list_name is not None:
            raw, offset = read_length_delimited(buffer, offset)
            item[sticker_list_name].append(parse_sticker(raw))
            continue

        if field_number == 18:
            value, offset = read_varint(buffer, offset)
            item["entindex"] = zigzag_decode(value)
            continue

        offset = skip_field(buffer, offset, wire_type)

    return item


def unwrap_masked_payload(data: bytes) -> bytes:
    if len(data) >= 5 and data[0] == 0x00:
        return data[1:-4]
    return data


def score_decoded_item(item: dict[str, Any]) -> int:
    score = 0

    if "defindex" in item:
        score += 4

    for field in SCORED_FIELDS:
        if field in item:
            score += 1

    score += len(item.get("stickers", []))
    score += len(item.get("keychains", []))
    score += len(item.get("variations", []))
    return score


def decode_masked_payload(hex_payload: str) -> tuple[str, dict[str, Any], bytes]:
    raw = binascii.unhexlify(hex_payload)

    if not raw:
        raise ValueError("Masked payload is empty")

    transformed = xor_mask(raw, raw[0])
    parsed = parse_econ_item(unwrap_masked_payload(transformed))
    score = score_decoded_item(parsed)

    if score < MIN_DECODE_SCORE:
        raise ValueError("Failed to decode inspect payload")

    return "xor_first_byte", parsed, transformed


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode masked CS2 inspect links")
    parser.add_argument("input", nargs="?", default=DEFAULT_INPUT)
    args = parser.parse_args()

    hex_payload = extract_hex_payload(args.input)
    transform, decoded, transformed = decode_masked_payload(hex_payload)

    result = {
        "hex_payload": hex_payload,
        "transform": transform,
        "raw_length": len(hex_payload) // 2,
        "transformed_prefix": transformed[:24].hex().upper(),
        "decoded": decoded,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()