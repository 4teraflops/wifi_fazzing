import pyrcrack
import asyncio
import time
import subprocess
from rich.prompt import Prompt
from rich.console import Console
from loguru import logger

logger.add(f'log/{__name__}.log', format='{time} {level} {message}', level='DEBUG', rotation='10 MB', compression='zip')
selected_interface = []


async def _system_command(command):
    try:
        command = subprocess.check_output(f'{command}; exit 0', shell=True)
        return command.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return 'Команда \n> {}\nзавершилась с кодом {}'.format(e.cmd, e.returncode)


async def check_mon(ints):
    res = {}
    for a in ints:
        if 'mon' in a:
            res[a] = True
        else:
            res[a] = False
    result = []
    for key in res:
        if res[key]:
            result.append(res[key])
            result.append(key)
        else:
            pass
    return result


async def scan():
    airmon = pyrcrack.AirmonNg()
    # Select interface
    console = Console()
    console.clear()
    console.show_cursor(False)
    interfaces = await airmon.interfaces
    ints = [a.interface for a in interfaces]
    mon_check = await check_mon(ints)
    if mon_check:
        mon_int = mon_check[1]
        console.print(f'Monitor mode detected. Interface - {mon_int}...', end='')
        await _system_command(f'ifconfig {mon_int} down')
        await _system_command(f'iwconfig {mon_int} mode managed')
        await _system_command(f'ifconfig {mon_int} up')
        await _system_command('service NetworkManager restart')
        await asyncio.sleep(15)
        console.print('OK')
    # TO DO default, numbers
    interface = Prompt.ask('Select an interface', choices=[a.interface for a in interfaces])
    selected_interface.append(interface)
    # Monitor mode + scan
    async with airmon(interface) as mon:
        async with pyrcrack.AirodumpNg() as pdump:
            async for aps in pdump(mon.monitor_interface):
                console.clear()
                console.print(aps.table)
                await asyncio.sleep(5)
                break  # So notebook execution doesn't get stuck here
    #await asyncio.sleep(30)


async def main():
    try:
        await scan()
    except KeyboardInterrupt:
        # how asyncio work?
        if selected_interface:
            interface_name = selected_interface[0] + 'mon'
            #print(f'Interface name: {interface_name}')
            #print('Back to managed mode...')
            await _system_command(f'ifconfig {interface_name} down')
            await _system_command(f'iwconfig {interface_name} mode managed')
            await _system_command(f'ifconfig {interface_name} up')
            await _system_command('service NetworkManager restart')
            #_system_command(f'ifconfig {ints[0]} up')
            print('\nGood Bye!')
        else:
            print('\nGood Bye!')


if __name__ == '__main__':
    asyncio.run(main())
