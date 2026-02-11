from libprobe.probe import Probe
from lib.check.certificates import CheckCertificates
from lib.check.ports import CheckPorts
from lib.version import __version__ as version


if __name__ == '__main__':
    checks = (
        CheckCertificates,
        CheckPorts
    )

    probe = Probe("tcp", version, checks)

    probe.start()
