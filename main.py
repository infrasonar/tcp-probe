from libprobe.probe import Probe
from lib.check.certificates import check_certificates
from lib.check.ports import check_ports
from lib.version import __version__ as version


if __name__ == '__main__':
    checks = {
        'certificates': check_certificates,
        'ports': check_ports
    }

    probe = Probe("tcp", version, checks)

    probe.start()
