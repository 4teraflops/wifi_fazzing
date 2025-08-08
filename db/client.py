import psycopg2
from psycopg2 import Error
from dotenv import load_dotenv
import os
from loguru import logger

logger.add(f'log/{__name__}.log', format='{time} {level} {message}', level='DEBUG', rotation='10 MB', compression='zip')


try:
    logger.info("connecting to DB...")
    # Подключение к существующей базе данных
    load_dotenv()
    conn = psycopg2.connect(
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        database=os.getenv("DATABASE")
    )


except (Exception, Error) as error:
    logger.info("Ошибка при работе с PostgreSQL", error)


def check_bssid_in_tbl(bssid):
    cursor = conn.cursor()

    # Проверяем, существует ли запись с таким bssid
    select_query = f"SELECT id FROM networks WHERE bssid = '{bssid}'"
    cursor.execute(select_query)
    result = cursor.fetchone()

    conn.commit()
    cursor.close()

    return result


def check_tables(rebuild_db=False):
    logger.info("OK")
    logger.info('Check_tables in bd...', end='')
    cursor = conn.cursor()

    if rebuild_db:
        try:
            cursor.execute("DROP table *")
            conn.commit()
            cursor.close()
        except psycopg2.errors.UndefinedTable:
            logger.info("Нечего ребилдить, таблица probe_requests не найдена.")
            conn.commit()
            cursor.close()
    cursor.execute("SELECT version();")
    cursor.execute("SELECT tablename FROM pg_catalog.pg_tables;")
    tables = cursor.fetchall()
    res = []

    for table in tables:
        res.append(table[0])
    if 'probe_requests' not in res:
        cursor.execute("CREATE TABLE probe_requests"
                       "(id serial not null primary key,"
                       "timestamp TIMESTAMPTZ NOT NULL, s_mac MACADDR NOT NULL, "
                       "essid VARCHAR(32), manufacturer varchar(150) NOT NULL, "
                       "anti_signal integer NOT NULL)")
        logger.info('Table probe_requests created.')

    if 'networks' not in res:
        cursor.execute(
            "CREATE TABLE public.networks"
            "(id serial NOT NULL,"
            "bssid macaddr NOT NULL,"
            "essid varchar(32),"
            "timestamp TIMESTAMPTZ NOT NULL,"
            "anti_signal integer,"
            "channel integer,"
            "PRIMARY KEY (id))"
            )
        logger.info('Table networks created.')

    conn.commit()
    cursor.close()
    logger.info('OK')


def insert_in_probe_requests_tbl(timestamp, s_mac, essid, manufacturer, anti_signal):
    cursor = conn.cursor()

    if essid == '':
        insert_query = f'''
            INSERT INTO probe_requests (timestamp, s_mac, essid, manufacturer, anti_signal) 
            VALUES ('{timestamp}', '{s_mac}', 'NULL', '{manufacturer}', '{anti_signal}')
        '''
    else:
        insert_query = f'''
            INSERT INTO probe_requests (timestamp, s_mac, essid, manufacturer, anti_signal) 
            VALUES ('{timestamp}', '{s_mac}', '{essid}', '{manufacturer}', '{anti_signal}')
        '''
    cursor.execute(insert_query)
    conn.commit()
    cursor.close()


def insert_in_networks_tbl(bssid, essid, timestamp, anti_signal, channel):
    cursor = conn.cursor()

    result = check_bssid_in_tbl(bssid)
    # Если запись с таким bssid не найдена, вставляем новую запись
    if result is None:

        insert_query = f'''
            INSERT INTO networks (bssid, essid, timestamp, anti_signal, channel)
            VALUES ('{bssid}', '{essid}', '{timestamp}', '{anti_signal}', '{channel}')
        '''

        cursor.execute(insert_query)
        logger.info(f"Запись добавлена в таблицу networks: bssid={bssid}, essid={essid}")
        conn.commit()
        cursor.close()
    else:
        logger.info(f"Запись с bssid {bssid} уже существует. Вставка пропущена.")
        cursor.close()
