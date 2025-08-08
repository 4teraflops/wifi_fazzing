from multiprocessing import Process, Queue
from app import handlers
from db import client
from loguru import logger
import traceback
import time

logger.add(f'log/{__name__}.log', format='{time} {level} {message}', level='DEBUG', rotation='10 MB', compression='zip')


def start_sniffing_with_error_handling(interface, handler, error_queue):
    try:
        handlers.start_sniffing(interface, handler)
    except Exception as e:
        # Сохраняем тип исключения, его строковое представление и трассировку стека
        error_info = {
            'type': type(e).__name__,
            'message': str(e),
            'traceback': traceback.format_exc()
        }
        error_queue.put(error_info)
    finally:
        # Убедитесь, что ресурсы освобождены (например, закрыты сокеты)
        pass


if __name__ == '__main__':
    interface = 'wlxd03745484a48'
    #logger.info(f'interface: {interface}')
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
                error_info = error_queue.get()
                logger.error(f"[ERROR] Exception in child process: {error_info['message']}")
                logger.error(f"Type: {error_info['type']}")
                logger.error(f"Traceback:\n{error_info['traceback']}")
                d11_probe_sniff.terminate()
                handshakes_sniff.terminate()
                break
            time.sleep(0.1)  # избегаем busy waiting

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
