#!/usr/bin/env python3

import struct
from scapy.packet import Packet, Raw
from scapy.fields import IntField, XIntField

class TestPacket(Packet):

    fields_desc = [
        IntField("full_len", 0),
        IntField("self_len", 0),
        XIntField("dummy", default=10)
    ]

    def post_build(self, pkt, pay):
        if not self.full_len:
            full_len = len(pkt)+len(pay)
            pkt = struct.pack('>i', full_len) + pkt[4:]
        if not self.self_len:
            self_len = len(pkt)
            pkt = pkt[:4] + struct.pack('>i', self_len) + pkt[8:]
        return pkt

test = TestPacket(dummy=19)
test.show2()
print(repr(bytes(test)))

test = TestPacket(dummy=0xFFFFFFFF)/Raw(b"testtest")
test.show2()
print(repr(bytes(test)))
