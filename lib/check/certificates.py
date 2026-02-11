import logging
import xml.etree.ElementTree as ET
from libprobe.asset import Asset
from libprobe.check import Check
from libprobe.exceptions import CheckException, IgnoreResultException, \
    NoCountException
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

    _not_before = get_text('validity', 'notBefore')
    assert _not_before is not None
    not_before = get_ts_from_time_str(_not_before[:19])

    _not_after = get_text('validity', 'notAfter')
    assert _not_after is not None
    not_after = get_ts_from_time_str(_not_after[:19])

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
    cert = f'{host}:{port}'
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
            name = f'{cert}-{protocol}'
            response_data.append({
                'name': name,
                'sslCert': cert,
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
    assert runstats is not None, 'failed to find runstats/finished'
    exit_status = runstats.attrib['exit']
    if exit_status != 'success':
        msg = f'Nmap exit status: {exit_status}'
        raise Exception(msg)
    summary = runstats.attrib['summary']
    if '; 0 IP addresses' in summary:
        raise Exception(summary)

    return root


def parse(string, address):
    root = _parse_xml(string)
    ssl_cert = []
    ssl_enum_ciphers = []

    for host in root.iter('host'):
        try:
            _hostname = host.find('hostnames/hostname')
            assert _hostname is not None, 'failed to find hostnames/hostname'
            hostname = _hostname.attrib['name']
        except Exception:
            hostname = address

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

    result = {}

    if ssl_cert:
        result['sslCert'] = ssl_cert

    if ssl_enum_ciphers:
        result['sslEnumCiphers'] = ssl_enum_ciphers

    return result


class CheckCertificates(Check):
    key = 'certificates'
    unchanged_eol = 14400

    @staticmethod
    async def run(asset: Asset, local_config: dict, config: dict) -> dict:
        address = config.get('address')
        if not address:
            address = asset.name
        check_certificate_ports = config.get('checkCertificatePorts')

        logging.debug(
            f'run certificate check: {address} '
            f'ports: {check_certificate_ports}')
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
                if not response_data:
                    logging.warning(
                        f'Both sslCert and sslEnumCiphers empty; {asset}')
                    raise IgnoreResultException()

            except ET.ParseError as e:
                raise CheckException(f'Nmap parse error: {e.msg}')

            except (CheckException, IgnoreResultException):
                raise

            except Exception as e:
                error_msg = str(e) or type(e).__name__
                logging.exception(f'query error: {error_msg}; {asset}')
                raise CheckException(error_msg)

            raise NoCountException('do not count certificates', response_data)
        else:
            # return empty check result; types are optional
            raise NoCountException('no certificates', {})
