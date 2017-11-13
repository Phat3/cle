import struct
import logging
from elftools.elf import elffile

from .elf import ELF
from .. import register_backend
from ...address_translator import AT
from ...errors import CLEError, CLECompatibilityError

l = logging.getLogger('cle.elfko')


class ELFKo(ELF):
    """
    Loader class for ELF ko (Kernel modules) files.
    """

    def __init__(self, binary, **kwargs):
        super(ELFKo, self).__init__(binary, **kwargs)
        self.symtab = None
        self.strtab = None
        self._apply_kernel_relocs()

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        identstring = stream.read(0x1000)
        stream.seek(0)
        if identstring.startswith('\x7fELF'):
            elf_file = elffile.ELFFile(stream)
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
        """
        Patch unknown symbols if some other module previously loaded
        exported the symbolwe want
        """
        if self._get_symtab_and_strtab():
            self._simplify_symbols()

    def _get_symtab_and_strtab(self):
        """
        Check if there is a section marked as SYMTAB.
        If so get the associated strtab also.
        
        :return : True if the symtab is found otherwise false
        """
        for sec in self.reader.iter_sections():
            if sec.header["sh_type"] == "SHT_SYMTAB":
                # TODO: Is it safe to assume only one symtab and related strtab?
                #       It seems so from the kernel code.
                self.symtab = sec
                self.strtab = self.reader.get_section(sec.header["sh_link"])
                return True
        return False

    def _simplify_symbols(self):
        """
        Simulate the lookup inside the kernel symbol table.
        This table is simulated throug the extern object of angr.
        Every time a module export a symbol a new entry is created inside the extern object.
        Here we just query the symbol that we want to simplyfy and if it is present
        inside the extern object we patch it with the correct address.

        This is needed in order to preserve dependency among the modules we want to analyze
        """
        for sym in self.symtab.iter_symbols():
            if sym.entry["st_shndx"] == "SHN_COMMON":
                l.debug("Found symbol %r with header SHN_COMMON... Nothing to do...", sym.name)
            elif sym.entry["st_shndx"] == "SHN_ABS":
                l.debug("Found symbol %r with header SHN_ABS pointing at %r... Nothing to do...", sym.name, sym.entry["st_value"])
            elif sym.entry["st_shndx"] == "SHN_LIVEPATCH":
                l.debug("Found symbol %r with header SHN_LIVEPATCH... Nothing to do...", sym.name)
            elif sym.entry["st_shndx"] == "SHN_UNDEF":
                l.debug("Found symbol %r with header SHN_UNDEF... Need to simplfy", sym.name)
                # TODO: Check in extern if something is found?
            else:
                l.debug("Found symbol %r with real section header", sym.name)

register_backend('elfko', ELFKo)
