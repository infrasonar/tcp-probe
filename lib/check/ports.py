import logging
import xml.etree.ElementTree as ET
from libprobe.asset import Asset
from libprobe.exceptions import CheckException, IgnoreResultException
from ..nmapquery import run


def parse(data):
    response_data = []
    root = ET.fromstring(data)
    for host in root.findall('host'):
        for port in host.findall('ports/port'):
            protocol = port.attrib['protocol']
            portid = port.attrib['portid']
            state = port.find('state')
            name = f'{protocol}:{portid}'

            response_data.append({
                'name': name,  # (str)
                'state': state.attrib['state'],  # (str)
                'reason': state.attrib['reason'],  # (str)
                'reasonTTL': int(state.attrib['reason_ttl'])  # (int)
            })

    return response_data


async def check_ports(
        asset: Asset,
        asset_config: dict,
        check_config: dict) -> dict:
    address = check_config.get('address')
    if not address:
        address = asset.name
    check_ports = check_config.get('checkPorts')

    logging.debug(f'run ports check: {address} ports: {check_ports}')
    if check_ports:
        params = [
            'nmap',
            # first timeout at a low value for a port ping
            # retry at most twice but with a max timeout of 750ms
            # nmap gradually ramps up the timeout to the max-rtt-timeout
            # value. The settings used to be T4
            '--max-rtt-timeout', '750ms',
            '--min-rtt-timeout', '50ms',
            '--initial-rtt-timeout', '80ms',
            '--host-timeout', '10s',
            '--max-retries', '2',
            '--max-scan-delay', '3ms',  # the delay between scan packets
            '--version-intensity', '5',
            # The lower-numbered probes are effective
            # against a wide variety of common services,
            # while the higher-numbered ones are rarely useful.
            # default = 7
            '-oX',
            '-',
            f"-p {','.join(map(str, check_ports))}",
            address
        ]
        response_data = {}
        try:
            data = await run(params)
            response_data['port'] = parse(data)

        except ET.ParseError as e:
            raise CheckException(f'Nmap parse error: {e.msg}')

        except Exception as e:
            error_msg = str(e) or type(e).__name__
            logging.exception(f'query error: {error_msg}; {asset}')
            raise CheckException(error_msg)

        return response_data
    else:
        raise IgnoreResultException()
