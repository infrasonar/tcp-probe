from libprobe.probe import Probe
from lib.check.dummy import check_dummy
from lib.version import __version__ as version


if __name__ == '__main__':
    checks = {
        'dummy': check_dummy
    }

    probe = Probe("tcp", version, checks)

    probe.start()
