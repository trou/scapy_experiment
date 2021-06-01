#!/usr/bin/env python3

import struct
from scapy.packet import Packet, Raw, RawVal
from scapy.compat import raw
from scapy.fields import IntField, XIntField, StrFixedLenField, Field

class PacketFieldOffset(Packet):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields_off = {}

    def self_build(self, field_pos_list=None):
        self.raw_packet_cache = None
        p = b""
        for f in self.fields_desc:
            val = self.getfieldval(f.name)
            self.fields_off[f] = len(p)
            if isinstance(val, RawVal):
                sval = raw(val)
                p += sval
                if field_pos_list is not None:
                    field_pos_list.append((f.name, sval.encode("string_escape"), len(p), len(sval)))  # noqa: E501
            else:
                p = f.addfield(self, p, val)
        return super().self_build(field_pos_list)

    def post_build(self, pkt, pay):
        for f_name, lbd in self.post_value.items():
            if not getattr(self, f_name, None):
                f = self.get_field(f_name)
                off = self.fields_off[f]
                start = f.addfield(pkt, pkt[:off], lbd(pkt, pay))
                pkt = start + pkt[len(start):]
        return pkt+pay

class AsciiIntField(StrFixedLenField):
    """
    Field containing an ASCII encoded int
    """
    __slots__ = ["length"]

    def __init__(self, *args, **kwargs):
        self.length = kwargs["length"]
        super().__init__(*args, **kwargs)

    def m2i(self, pkt, x):
        return int(x, 16)

    def i2m(self, pkt, x):
        if x is None:
            return b""
        elif isinstance(x, int):
            return "{:0{width}x}".format(x, width=self.length).encode()
        else:
            return x

class TestPacket(PacketFieldOffset):

    fields_desc = [
        AsciiIntField("full_len", 0, length=8),
        IntField("self_len", 0),
        XIntField("dummy", default=10)
    ]

    post_value = {"full_len" : (lambda pkt, pay: len(pkt)+len(pay)),
                  "self_len" : (lambda pkt, pay: len(pkt))}

test = TestPacket(dummy=19)
test.show2()
print(repr(bytes(test)))

test = TestPacket(dummy=0xFFFFFFFF)/Raw(b"testtest")
test.show2()
print(repr(bytes(test)))
