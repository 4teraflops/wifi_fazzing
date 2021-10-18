from scapy.all import sniff
from scapy.layers.dot11 import Dot11ProbeReq, RadioTap, Dot11Auth, Dot11Beacon
from time import localtime, strftime, strptime
from src import manager
from db import client


def probe_packet_handler(packet):
    if packet.haslayer(Dot11ProbeReq):
        if packet.type == 0 and packet.subtype == 4:
            timestamp_src = packet.getlayer(RadioTap).time
            timestamp = strftime("%Y-%m-%d %H:%M:%S %Z", localtime(timestamp_src))
            #d_mac = packet.getlayer(RadioTap).addr1  # Нет смысла это чекать. Все уже шлют тут широковещалку.
            s_mac = packet.getlayer(RadioTap).addr2
            #bssid = packet.getlayer(RadioTap).addr3  # Нет смысла это чекать. Все уже шлют тут широковещалку.
            manufacturer = manager.get_s_mac_oui(s_mac)
            anti_signal = packet.getlayer(RadioTap).dBm_AntSignal
            #not_decoded = packet.getlayer(RadioTap).notdecoded
            try:
                essid = packet.getlayer(Dot11ProbeReq).info.decode("utf-8")
                if essid:
                    print(f'timestamp: {timestamp} \nsource_mac: {s_mac} \nessid: {essid} \nmanufacturer: {manufacturer} \nanti_signal: {anti_signal}\n')
                    #packet.show()
                    client.insert_in_probe_requests_tbl(timestamp, s_mac, essid, manufacturer, anti_signal)
            # The ESSID is not a valid UTF-8 string.
            except UnicodeDecodeError:
                essid = 'Unknown ESSID'
                print(f'{timestamp} | {s_mac}, | {essid} | {manufacturer} | {anti_signal}')
                client.insert_in_probe_requests_tbl(timestamp, s_mac, essid, manufacturer, anti_signal)


def auth_packet_handler(packet):
    if packet.haslayer(Dot11Auth):
        if packet.type == 0 and packet.subtype == 11:
            packet.show()


def start_sniffing(iface, prn):
     sniff(iface=iface, prn=prn)