import psycopg2
from psycopg2 import Error

try:
    # Подключение к существующей базе данных
    conn = psycopg2.connect(
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432",
        database='pgdb'
    )
except (Exception, Error) as error:
    print("Ошибка при работе с PostgreSQL", error)


def check_tables(rebuild_db=False):
    print('Check_tables in bd...', end='')
    cursor = conn.cursor()
    if rebuild_db:
        cursor.execute("DROP table probe_requests")
        print('Drop table probe_requests...')
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
        print('Table probe_requests created.')
    conn.commit()
    print('OK')


def insert_in_probe_requests_tbl(timestamp, s_mac, essid, manufacturer, anti_signal):
    cursor = conn.cursor()
    if essid == '':
        insert_query = f'''INSERT INTO probe_requests (timestamp, s_mac, essid, manufacturer, anti_signal) VALUES ('{timestamp}', '{s_mac}', 'NULL', '{manufacturer}', '{anti_signal}')'''
    else:
        insert_query = f'''INSERT INTO probe_requests (timestamp, s_mac, essid, manufacturer, anti_signal) VALUES ('{timestamp}', '{s_mac}', '{essid}', '{manufacturer}', '{anti_signal}')'''
    cursor.execute(insert_query)
    conn.commit()

