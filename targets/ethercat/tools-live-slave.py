#!/usr/bin/env python3
"""Minimal EtherCAT slave simulator for live two-process reproduction, over a real veth link.
Mirrors the C++ datagram-generator responder used in harness-coe.cc/harness-soeread.cc: acks
FPWR, answers small (<=4 byte) FPRD as an SM-status poll (0x08 set), answers larger FPRD with the
given payload file's bytes (the interesting content -- what the "slave" claims in its mailbox
response)."""
import socket
import struct
import sys
import time

ETH_P_ECAT = 0x88A4
EC_CMD_FPWR = 5
EC_CMD_FPRD = 4
EC_ECATTYPE = 0x1000


def rd16(b, off):
    return b[off] | (b[off + 1] << 8)


def wr16(v):
    return bytes([v & 0xFF, (v >> 8) & 0xFF])


def build_response(idx_byte, requested_dlength, payload):
    # Ethernet header: dst=broadcast, src=priMAC (0101:0101:0101), etype=ETH_P_ECAT (big-endian)
    eth = bytes([0xFF] * 6) + bytes([0x01, 0x01] * 3) + struct.pack(">H", ETH_P_ECAT)
    dg = wr16(EC_ECATTYPE + 12 + requested_dlength) + bytes([0, idx_byte]) + wr16(0x1001) + wr16(0) + wr16(requested_dlength) + wr16(0)
    n = min(len(payload), requested_dlength)
    data = payload[:n] + bytes(requested_dlength - n)
    wkc = wr16(1)
    return eth + dg + data + wkc


def main():
    iface, payload_path = sys.argv[1], sys.argv[2]
    with open(payload_path, "rb") as f:
        payload = f.read()
    print(f"Loaded {len(payload)} byte payload, listening on {iface}")

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ECAT))
    s.bind((iface, 0))

    responded = 0
    while responded < 32:
        frame = s.recv(2048)
        if len(frame) < 26:
            continue
        if frame[12] != 0x88 or frame[13] != 0xA4:
            continue
        dg = frame[14:]
        command = dg[2]
        idx_byte = dg[3]
        dlength = rd16(dg, 8)
        if command == EC_CMD_FPWR:
            resp = build_response(idx_byte, dlength, b"")
        elif command == EC_CMD_FPRD:
            if dlength <= 4:
                resp = build_response(idx_byte, dlength, bytes([0x08]))
            else:
                resp = build_response(idx_byte, dlength, payload)
        else:
            continue
        s.send(resp)
        responded += 1
        print(f"answered command={command} idx={idx_byte} dlength={dlength} t={time.time():.4f} "
              f"resp_head={resp[14:14+20].hex()}")


if __name__ == "__main__":
    main()
