import os
from sys import intern
from dotenv import load_dotenv
from netaddr import EUI, NotRegisteredError
import requests
import json
import subprocess
from db.client import check_tables


def _system_command(command):
    try:
        command = subprocess.check_output(f'{command}; exit 0', shell=True)
        return command.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return 'Команда \n> {}\nзавершилась с кодом {}'.format(e.cmd, e.returncode)


def do_alarm(t_alarmtext):
    load_dotenv()
    webhook_url = os.getenv("WEBHOOK_URL")
    admin_id = os.getenv("ADMIN_ID")
    headers = {"Content-type": "application/json"}
    payload = {"text": f"{t_alarmtext}", "chat_id": f"{admin_id}"}
    requests.post(url=webhook_url, data=json.dumps(payload), headers=headers)


def get_s_mac_oui(s_mac):
    """
    OUI of the station's MAC address as a string.
    The value is cached once computed.
    """
    # pylint: disable=no-member
    try:
        s_mac_oui = EUI(s_mac).oui.registration().org
    except NotRegisteredError:
        s_mac_oui = "Unknown Device"
    return s_mac_oui


def check_interfaces():
    interfaces = _system_command('airmon-ng')
    res = {}
    for int in interfaces.replace('\n', '').split('\t'):
        mon = 'mon' in int
        res[int] = mon
    result = []
    for key in res:
        if res[key] is True:
            result.append(key)
            result.append(res[key])
        else:
            pass
    return result


def preparation_interface():
    print('Check interfaces...')
    if check_interfaces():
        interface = check_interfaces()[0]
        print(f'mon interface discovered - {interface}')
        return interface
    else:
        try:
            print('Trying wlan0 -> mon mode...', end='')
            #print(_system_command('airmon-ng start wlan0'))
            _system_command('airmon-ng start wlan0')
            interface = check_interfaces()[0]
            #print(f"interface:{check_interfaces()[0]}")
            print('OK')
            return interface
        except IndexError:
            return "Interface wlan0 not found"
