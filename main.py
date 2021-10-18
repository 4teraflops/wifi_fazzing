from src import manager
from app import handlers
from db import client
from multiprocessing import Process


if __name__ == '__main__':
    interface = 'wlan1'
    #interface = manager.preparation_interface()
    d11_probe_sniff = Process(target=handlers.start_sniffing, args=(interface, handlers.probe_packet_handler))
    auth_packet_sniff = Process(target=handlers.start_sniffing, args=(interface, handlers.auth_packet_handler))
    try:
        client.check_tables(rebuild_db=False)  # With rebuild mode
        d11_probe_sniff.start()
        auth_packet_sniff.start()

    except KeyboardInterrupt:
        print('Good bye!')
    #except Exception as e:
    #    t_alarmtext = f'wifi (main.py):\n {str(e)}'
    #    manager.do_alarm(t_alarmtext)
