import logging
import xml.etree.ElementTree as ET
from libprobe.asset import Asset
from libprobe.exceptions import CheckException, IgnoreResultException
from ..exceptions import UnresolvableException
from ..nmapquery import run
from ..utils import get_ts_from_time_str, get_ts_utc_now


def _parse_cert_info(node, host, port):
    if not node:
        return []

    def get_text(table=None, elem=None, allow_none=False):
        pth = f"table[@key='{table}']/elem[@key='{elem}']" if elem \
            else f"elem[@key='{table}']"
        nod = node.find(pth)
        if nod is None:
            if allow_none:
                return None
            else:
                raise Exception(f'unable to find {pth}')
        return nod.text

    not_before = get_ts_from_time_str(
        get_text('validity', 'notBefore')[:19])
    not_after = get_ts_from_time_str(
        get_text('validity', 'notAfter')[:19])
    now = get_ts_utc_now()

    is_valid = not_before <= now <= not_after
    expires_in = not_after - now

    name = f'{host}:{port}'
    return [{
        'name': name,
        'subject': '/'.join(map(
            lambda elem: f'{elem.attrib["key"]}={elem.text}',
            node.findall("table[@key='subject']/elem")
        )),
        'issuer': '/'.join(map(
            lambda elem: f'{elem.attrib["key"]}={elem.text}',
            node.findall("table[@key='issuer']/elem")
        )),
        'validNotBefore': not_before,
        'validNotAfter': not_after,
        'isValid': is_valid,
        'expiresIn': expires_in,
        'pubkeyType': get_text('pubkey', 'type'),
        'pubkeyBits': get_text('pubkey', 'bits'),
        'md5': get_text('md5'),
        'sha1': get_text('sha1'),
    }]


def _parse_ciphers_info(node, host, port):
    response_data = []
    if node:
        for protocol in node.findall('table'):
            ciphers = []
            for cipher in protocol.findall("table[@key='ciphers']/table"):
                name = cipher.find("elem[@key='name']").text
                strength = cipher.find("elem[@key='strength']").text

                ciphers.append(f'{name} - {strength}')

            warnings = []
            for warning in protocol.findall("table[@key='warnings']/elem"):
                warnings.append(warning.text)

            protocol = protocol.attrib["key"]
            name = f'{host}:{port}-{protocol}'
            response_data.append({
                'name': name,
                'protocol': protocol,
                'ciphers': '\r\n'.join(ciphers),
                'warnings': '\r\n'.join(warnings),
                'leastStrength': node.find(
                    "elem[@key='least strength']").text
            })

    return response_data


def _parse_xml(data):
    root = ET.fromstring(data)
    runstats = root.find('runstats/finished')
    if runstats.attrib['exit'] != 'success':
        raise Exception(data)
    summary = runstats.attrib['summary']
    if '; 0 IP addresses' in summary:
        raise UnresolvableException(summary)

    return root


def parse(string, address):
    root = _parse_xml(string)
    ssl_cert = []
    ssl_enum_ciphers = []

    for host in root.iter('host'):
        try:
            hostname = host.find(
                'hostnames/hostname').attrib['name']
        except Exception:
            hostname = address  # TODO waarom geen exceptie raisen hier?

        for port in host.iter('port'):
            portid = port.attrib['portid']

            cert = _parse_cert_info(
                port.find("script[@id='ssl-cert']"),
                hostname,
                portid
            )
            enum_ciphers = _parse_ciphers_info(
                port.find("script[@id='ssl-enum-ciphers']"),
                hostname,
                portid
            )

            ssl_cert.extend(cert)
            ssl_enum_ciphers.extend(enum_ciphers)

    return {
        'sslCert': ssl_cert,
        'sslEnumCiphers': ssl_enum_ciphers,
    }


async def check_certificates(
        asset: Asset,
        asset_config: dict,
        check_config: dict) -> dict:
    address = check_config.get('address')
    if not address:
        address = asset.name
    check_certificate_ports = check_config.get('checkCertificatePorts')

    logging.debug(
        f'run certificate check: {address} ports: {check_certificate_ports}')
    if check_certificate_ports:
        params = [
            'nmap',
            '--script',
            '+ssl-cert,+ssl-enum-ciphers',
            '-oX',
            '-',
            f"-p {','.join(map(str, check_certificate_ports))}",
            address
        ]

        response_data = {}
        try:
            data = await run(params)
            response_data = parse(data, address)
            if not response_data['sslCert']:
                raise IgnoreResultException((
                    'Checked Ports: '
                    f"{' '.join(map(str, check_certificate_ports))}"

                ))

        except ET.ParseError as e:
            raise CheckException(f'Nmap parse error: {e.msg}')

        except Exception as e:
            error_msg = str(e) or type(e).__name__
            logging.exception(f'query error: {error_msg}; {asset}')
            raise CheckException(error_msg)

        return response_data
    else:
        raise IgnoreResultException(
            'CheckCertificates did not run; no ports are provided')
