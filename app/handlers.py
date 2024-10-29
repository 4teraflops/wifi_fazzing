from datetime import datetime
from scapy.all import sniff
from scapy.layers.dot11 import Dot11ProbeReq, RadioTap, Dot11Beacon, Dot11, Dot11Elt, Dot11ProbeResp
from time import localtime, strftime
from scapy.layers.eap import EAPOL
from scapy.utils import wrpcap
import manager
from db import client

handshake_packets = []  # Для хранения handshake пакетов
network_info = {}  # Словарь для хранения всех обнаруженных сетей {BSSID: ESSID}


def save_network_to_dict(bssid, essid, timestamp, anti_signal, channel):
    """
    Сохраняем BSSID и ESSID в словарь
    """
    if bssid not in network_info:
        network_info[bssid] = {"ESSID": essid, "timestamp": timestamp, "anti_signal": anti_signal, "channel": channel}
        print(f"[Dict] Network: BSSID: {bssid} {network_info[bssid]}")


def get_essid_from_dict(bssid):
    """
    Извлекаем ESSID из словаря по BSSID
    """
    return network_info.get(bssid, "Unknown_ESSID")


def is_valid_handshake(packets):
    """
    Проверка валидности собранных пакетов для 4-way handshake
    """
    # Должно быть 4 пакета
    if len(packets) != 4:
        print("[Error] Handshake не завершён: недостаточно пакетов")
        return False

    # Проверяем MAC-адреса (адрес точки доступа и клиента должны совпадать)
    ap_mac = packets[0].getlayer(Dot11).addr1  # MAC точки доступа
    client_mac = packets[0].getlayer(Dot11).addr2  # MAC клиента

    for packet in packets:
        if not packet.haslayer(EAPOL):
            print("[Error] В пакете отсутствует EAPOL")
            return False
        if packet.getlayer(Dot11).addr1 != ap_mac or packet.getlayer(Dot11).addr2 != client_mac:
            print("[Error] MAC-адреса не совпадают")
            return False

    print("[Success] Собрано корректное рукопожатие")
    return True


def extract_from_beacons(packet):
    """
    Функция для извлечения имени сети (ESSID) из Beacon или Probe Response пакетов
    """
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        bssid = packet[Dot11].addr3  # Извлекаем BSSID
        essid = packet[Dot11Elt].info.decode()  # Извлекаем ESSID
        if packet.haslayer(Dot11Beacon):
            timestamp = packet[Dot11Beacon].timestamp
        else:
            timestamp = datetime.now()
        # Уровень сигнала
        if packet.haslayer(RadioTap):
            signal_strength = packet.dBm_AntSignal
        else:
            signal_strength = "Unknown"

        # Извлекаем канал
        ds_param_set = packet[Dot11Elt:3]
        if ds_param_set and ds_param_set.ID == 3:
            channel = ds_param_set.info[0]
        else:
            channel = "Unknown"
        #Сохраняем в словарь
        save_network_to_dict(bssid, essid, timestamp, anti_signal=signal_strength, channel=channel)
        #save_network_to_dict(bssid, essid)
        #print(f"[Network detected] ESSID: {essid}, BSSID: {bssid}")


def probe_packet_handler(packet):
    '''
    Функция смотрит какие вокруг есть probe requests и записывает все что видит в базу
    '''

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
                    print(f'\nTYPE: probe request | timestamp: {timestamp} | source_mac: {s_mac} | essid: {essid} | anti_signal: {anti_signal}') # Manufacturer не выводим, нафиг надо
                    #packet.show()
                    client.insert_in_probe_requests_tbl(timestamp, s_mac, essid, manufacturer, anti_signal)
            # The ESSID is not a valid UTF-8 string.
            except UnicodeDecodeError:
                essid = 'Unknown ESSID'
                print(f'\nTYPE: probe request| {timestamp} | {s_mac}, | {essid} | {manufacturer} | {anti_signal}')
                client.insert_in_probe_requests_tbl(timestamp, s_mac, essid, manufacturer, anti_signal)



def handshake_packet_handler(packet):
    """
    Обработчик для перехвата пакетов EAPOL (4-way handshake)
    """
    if packet.haslayer(EAPOL):
        print(f"[Handshake packet] {packet.summary()}")
        handshake_packets.append(packet)  # Добавляем пакет в список
        if len(handshake_packets) == 4:  # Проверка, если собраны все 4 пакета рукопожатия
            if is_valid_handshake(handshake_packets):  # Проверка валидности пакетов
                # Извлекаем BSSID из EAPOL пакетов
                bssid = handshake_packets[0].getlayer(Dot11).addr1  # Это BSSID
                # Извлекаем ESSID из словаря
                essid = get_essid_from_dict(bssid)
                # Создаём имя файла на основе ESSID и BSSID
                filename = f"{essid}_{bssid}_handshake.cap"

                wrpcap(filename, handshake_packets)  # Сохраняем пакеты в .cap файл
                print("Handshake capture complete! Saved as handshake.cap")
            else:
                print("Invalid handshake, capture discarded.")
            handshake_packets.clear()  # Очищаем список после проверки


def process_packet(packet):
    """
    Универсальная функция для обработки всех пакетов
    """
    # Извлекаем ESSID и BSSID из Beacon или Probe Response
    extract_from_beacons(packet)
    # Обрабатываем Probe Request пакеты
    probe_packet_handler(packet)
    # Обрабатываем EAPOL (handshake) пакеты
    handshake_packet_handler(packet)


def start_sniffing(iface, prn):
    """
    Функция для начала перехвата пакетов
    """
    sniff(iface=iface, prn=process_packet, store=False)
