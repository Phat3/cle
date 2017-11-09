import struct
import elftools
import logging

from .elf import ELF
from .. import register_backend
from ...errors import CLEError, CLECompatibilityError

l = logging.getLogger('cle.elfko')


class ELFKo(ELF):
    """
    Loader class for ELF ko (Kernel modules) files.
    """

    def __init__(self, binary, **kwargs):
        super(ELFKo, self).__init__(binary, **kwargs)
        self._apply_kernel_relocs()

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        identstring = stream.read(0x1000)
        stream.seek(0)
        if identstring.startswith('\x7fELF'):
            elf_file = elftools.elf.elffile.ELFFile(stream)
            # To understatnd if the file is a kernel module we can check if
            # one of these special section is present
            #
            # TODO: fogure out if there is a clever way to do it
            if (elf_file.get_section_by_name("__ksymtab") is not None) or \
            (elf_file.get_section_by_name(".modinfo") is not None) or \
            (elf_file.get_section_by_name(".gnu.linkonce.this_module") is not None):
                return True
            return False
        return False

    def _apply_kernel_relocs(self):
        pass

register_backend('elfko', ELFKo)
