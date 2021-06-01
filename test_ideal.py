#!/usr/bin/env python3

import struct
from scapy.packet import Packet, Raw
from scapy.fields import IntField, XIntField

class TestPacket(Packet):

    fields_desc = [
        PacketPayloadLen("full_len", default=0, fldtype=IntField),
        PacketLen("self_len", default=0, fldtype=IntField),
        XIntField("dummy", default=10)
    ]

