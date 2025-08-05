from multiprocessing import Process, Queue
from app import handlers
from db import client
from loguru import logger


logger.add(f'log/{__name__}.log', format='{time} {level} {message}', level='DEBUG', rotation='10 MB', compression='zip')

def start_sniffing_with_error_handling(interface, handler, error_queue):
    try:
        handlers.start_sniffing(interface, handler)
    except Exception as e:
        error_queue.put(e)  # Передаем исключение в очередь

if __name__ == '__main__':
    interface = 'wlan0'
    error_queue = Queue()  # Очередь для передачи ошибок

    # Создаем процессы с передачей очереди ошибок
    d11_probe_sniff = Process(target=start_sniffing_with_error_handling, args=(interface, handlers.probe_packet_handler, error_queue))
    handshakes_sniff = Process(target=start_sniffing_with_error_handling, args=(interface, handlers.auth_packet_handler, error_queue))

    try:
        client.check_tables(rebuild_db=False)  # Проверка базы данных
        d11_probe_sniff.start()
        handshakes_sniff.start()

        # Проверка очереди ошибок
        while True:
            if not error_queue.empty():
                error = error_queue.get()
                logger.error(f"[ERROR] Exception in child process: {error}")
                d11_probe_sniff.terminate()
                handshakes_sniff.terminate()
                break

        # Ожидаем завершения процессов
        d11_probe_sniff.join()
        handshakes_sniff.join()

    except KeyboardInterrupt:
        logger.info("\n[INFO] Sniffing stopped by user (Ctrl+C).")
        handshakes_sniff.terminate()  # Принудительно завершаем процесс
        d11_probe_sniff.terminate()

    finally:
        logger.info("[INFO] Cleaning up and exiting.")
        d11_probe_sniff.join()  # Убеждаемся, что процесс завершён
        handshakes_sniff.join()
