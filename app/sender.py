from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11AssoReq, Dot11Elt


class Dot11EltRates(Packet):
    """ Our own definition for the supported rates field """
    name = "802.11 Rates Information Element"
    # Our Test STA supports the rates 6, 9, 12, 18, 24, 36, 48 and 54 Mbps
    supported_rates = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]
    fields_desc = [ByteField("ID", 1), ByteField("len", len(supported_rates))]
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(index + 1), rate))


packet = Dot11(addr1="74:e5:43:31:e0:5f", addr2="ff:ff:ff:ff:ff:ff", addr3="74:e5:43:31:e0:5f")
Dot11AssoReq(cap=0x1100, listen_interval=0x00a)
Dot11Elt(ID=0, info="NETGEAR")
packet /= Dot11EltRates()
sendp(packet, iface="wlan1mon")
packet.show()