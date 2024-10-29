from app import handlers
from db import client
from multiprocessing import Process


if __name__ == '__main__':
    interface = 'wlan0'
    #interface = manager.preparation_interface()
    d11_probe_sniff = Process(target=handlers.start_sniffing, args=(interface, handlers.probe_packet_handler))
    handshakes_sniff = Process(target=handlers.start_sniffing, args=(interface, handlers.handshake_packet_handler))
    try:
        client.check_tables(rebuild_db=False)  # With rebuild mode
        d11_probe_sniff.start()
        handshakes_sniff.start()

        # Ожидаем завершения процессов
        d11_probe_sniff.join()
        handshakes_sniff.join()

    except KeyboardInterrupt:
        print("\n[INFO] Sniffing stopped by user (Ctrl+C).")
        handshakes_sniff.terminate() # Принудительно завершаем процесс
        d11_probe_sniff.terminate()

    finally:
        print("[INFO] Cleaning up and exiting.")
        d11_probe_sniff.join()  # Убеждаемся, что процесс завершён
        handshakes_sniff.join()
