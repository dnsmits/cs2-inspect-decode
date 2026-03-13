import argparse
import binascii
import json
import re
import struct
from typing import Any


DEFAULT_INPUT = (
    "steam://run/730//+csgo_econ_action_preview%204757F1EFEF8CEB465F5967AC466F4577437FB5D4FC9B44078E442F65375FEE9768B7"
)


def extract_hex_payload(value: str) -> str:
    match = re.search(r"csgo_econ_action_preview(?:%20| )([0-9A-Fa-f]+)$", value)
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

        if field_number in {1, 2, 6, 10, 11, 12}:
            value, offset = read_varint(buffer, offset)
            if field_number == 1:
                sticker["slot"] = value
            elif field_number == 2:
                sticker["sticker_id"] = value
            elif field_number == 6:
                sticker["tint_id"] = value
            elif field_number == 10:
                sticker["pattern"] = value
            elif field_number == 11:
                sticker["highlight_reel"] = value
            elif field_number == 12:
                sticker["wrapped_sticker"] = value
            continue

        if field_number in {3, 4, 5, 7, 8, 9}:
            raw_value, offset = read_fixed32(buffer, offset)
            value = fixed32_to_float(raw_value)
            if field_number == 3:
                sticker["wear"] = value
            elif field_number == 4:
                sticker["scale"] = value
            elif field_number == 5:
                sticker["rotation"] = value
            elif field_number == 7:
                sticker["offset_x"] = value
            elif field_number == 8:
                sticker["offset_y"] = value
            elif field_number == 9:
                sticker["offset_z"] = value
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

        if field_number in {1, 2, 3, 4, 5, 6, 8, 9, 10, 13, 14, 15, 16, 17, 19, 21, 23}:
            value, offset = read_varint(buffer, offset)
            if field_number == 1:
                item["accountid"] = value
            elif field_number == 2:
                item["itemid"] = value
            elif field_number == 3:
                item["defindex"] = value
            elif field_number == 4:
                item["paintindex"] = value
            elif field_number == 5:
                item["rarity"] = value
            elif field_number == 6:
                item["quality"] = value
            elif field_number == 8:
                item["paintseed"] = value
            elif field_number == 9:
                item["killeaterscoretype"] = value
            elif field_number == 10:
                item["killeatervalue"] = value
            elif field_number == 13:
                item["inventory"] = value
            elif field_number == 14:
                item["origin"] = value
            elif field_number == 15:
                item["questid"] = value
            elif field_number == 16:
                item["dropreason"] = value
            elif field_number == 17:
                item["musicindex"] = value
            elif field_number == 19:
                item["petindex"] = value
            elif field_number == 21:
                item["style"] = value
            elif field_number == 23:
                item["upgrade_level"] = value
            continue

        if field_number == 7:
            value, offset = read_varint(buffer, offset)
            item["paintwear"] = bytes_to_float_bits(value)
            continue

        if field_number == 11:
            raw, offset = read_length_delimited(buffer, offset)
            item["customname"] = raw.decode("utf-8")
            continue

        if field_number in {12, 20, 22}:
            raw, offset = read_length_delimited(buffer, offset)
            parsed = parse_sticker(raw)
            if field_number == 12:
                item["stickers"].append(parsed)
            elif field_number == 20:
                item["keychains"].append(parsed)
            elif field_number == 22:
                item["variations"].append(parsed)
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


def decode_masked_payload(hex_payload: str) -> tuple[str, dict[str, Any], bytes]:
    raw = binascii.unhexlify(hex_payload)

    if not raw:
        raise ValueError("Masked payload is empty")

    candidates = [
        ("plain", raw),
        # Some masked links use a per-payload XOR byte; first payload byte is the mask key.
        ("xor_first_byte", xor_mask(raw, raw[0])),
        ("xor_fb", xor_mask(raw, 0xFB)),
    ]

    last_error = None
    for name, transformed in candidates:
        try:
            parsed = parse_econ_item(unwrap_masked_payload(transformed))
            if parsed.get("defindex") and parsed.get("paintindex"):
                return name, parsed, transformed
        except Exception as error:
            last_error = error

    if last_error is not None:
        raise last_error
    raise ValueError("Failed to decode inspect payload")


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