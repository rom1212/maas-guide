from curtin import __version__ as old_version
import os
import subprocess

_PACKAGED_VERSION = '0.1.0~bzr505-0ubuntu1~16.04.1'
_PACKED_VERSION = '0.1.0~bzr505-0ubuntu1~16.04.1'


def version_string():
    """ Extract a version string from curtin source or version file"""

    if not _PACKAGED_VERSION.startswith('@@'):
        return _PACKAGED_VERSION

    if not _PACKED_VERSION.startswith('@@'):
        return _PACKED_VERSION

    revno = None
    version = old_version
    bzrdir = os.path.abspath(os.path.join(__file__, '..', '..', '.bzr'))
    if os.path.isdir(bzrdir):
        try:
            out = subprocess.check_output(['bzr', 'revno'], cwd=bzrdir)
            revno = out.decode('utf-8').strip()
            if revno:
                version += "~bzr%s" % revno
        except subprocess.CalledProcessError:
            pass

    return version
