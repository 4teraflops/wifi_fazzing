from scapy.all import sniff
from scapy.layers.dot11 import Dot11ProbeReq, RadioTap, Dot11Auth, Dot11Beacon
from time import localtime, strftime, strptime
from time import localtime, strftime
import os
from scapy.utils import wrpcap
from src import manager
from db import client
from loguru import logger


logger.add(f'log/{__name__}.log', format='{time} {level} {message}', level='DEBUG', rotation='10 MB', compression='zip')

# Создайте папку для хранения handshake файлов, если её нет
handshake_dir = "handshakes"
if not os.path.exists(handshake_dir):
    os.makedirs(handshake_dir)


def save_handshake_packet(packet, essid):
    """
    Сохраняет пакет в файл .cap в папке handshakes.
    """
    if not essid:
        return

    filename = os.path.join(handshake_dir, f"{essid}_handshake.cap")
    filepath = os.path.join("handshakes", filename)

    if not os.path.exists(filepath):
        try:
            wrpcap(filename, packet)
            logger.info(f"Handshake сохранен в файл: {filename}")
        except Exception as e:
            logger.error(f"Ошибка при сохранении файла: {str(e)}")


def extract_essid(packet):
    """
    Извлекает ESSID из пакета.
    """
    essid = None
    if packet.haslayer(Dot11ProbeReq):
        try:
            essid = packet.getlayer(Dot11ProbeReq).info.decode("utf-8")
        except UnicodeDecodeError:
            essid = 'Unknown ESSID'
    elif packet.haslayer(Dot11Auth) and packet.subtype == 0x0b:  #_subtype=11 (.authenticate response)
        if packet.getlayer(RadioTap).addr3:  # BSSID
            # Для authenticate пакетов, ESSID можно получить из beacon или probe response
            # В данном случае, предполагаем, что essid уже был извлечен и сохранен ранее
            pass
    return essid


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
                    logger.info(f'\ntimestamp: {timestamp} \nsource_mac: {s_mac} \nessid: {essid} \nmanufacturer: {manufacturer} \nanti_signal: {anti_signal}\n')
                    #packet.show()
                    client.insert_in_probe_requests_tbl(timestamp, s_mac, essid, manufacturer, anti_signal)
                    # Сохранить пакет в файл .cap
                    save_handshake_packet(packet, essid)
            # The ESSID is not a valid UTF-8 string.
            except UnicodeDecodeError:
                essid = 'Unknown ESSID'
                logger.info(f'\n{timestamp} | {s_mac}, | {essid} | {manufacturer} | {anti_signal}')
                # Записать данные в базу
                client.insert_in_probe_requests_tbl(timestamp, s_mac, essid, manufacturer, anti_signal)
                # Сохранить пакет в файл .cap
                save_handshake_packet(packet, essid)


def auth_packet_handler(packet):
    if packet.haslayer(Dot11Auth):
        if packet.type == 0 and packet.subtype == 11:
            packet.show()
            # Извлекаем ESSID
            essid = extract_essid(packet)
            # Сохранить пакет в файл .cap
            save_handshake_packet(packet, essid)


def start_sniffing(iface, prn):
     sniff(iface=iface, prn=prn)
