import logging
from elftools.elf import elffile

from .elf import ELF
from .. import register_backend

l = logging.getLogger('cle.elfko')


class ELFKo(ELF):
    """
    Loader class for ELF ko (Kernel modules) files.
    """

    def __init__(self, binary, **kwargs):
        super(ELFKo, self).__init__(binary, **kwargs)
        self._register_dependency()

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


    def _register_dependency(self):
        """
        Check if the module serves as a dependency of another module
        included in the analysis. If this is the case the module is added as
        dependent object of the main module

        TODO: implement this thing recursively
              (i. e. mod_1 --- depends on ---> mod_2 --- depends on ---> mod_3
              we need to put mod_3 as a dependency object of mod_2 and not as
              dependency of mod_1).

              Probably it's gonna work also now if the order of loading is
              given to angr before. Angr will load first the module
              without any dependency (mod_3), then the other one that depends
              only on mod_3 (mod_2) and so on.
        """
        if self.loader.main_object is not None and \
           "__ksymtab" in self.sections_map.keys():
           # add ourself as dependency of main module
           self.loader.main_object.deps.append(self.provides)
           # we need to export our symbols
           self._register_exports()


    def _register_exports(self):
        """
        Angr by default does not parse sections __ksymtab and __ksymtab_strings
        because it does not support kernel modules (these section are present only in these modules).
        These two sections contains all exported symbols which can be used by other
        modules.

        In order to easily support this feature we can use this simple trick: at this point
        angr has already loaded the binary and parsed all symbols correctly (all of them have already the
        correct rebased address), but the ones present in the __ksymtab are not marked as "exported".
        To fx this we can just parse the __ksymtab_strings and mark as "exported" every
        symbol related to every string found in this section.

        If we don't do this we are gonna have several problems such as:
            - Globals imported form other module will not be referenced correctly
            - Functions imported from other modules will be substituted by the default
              SimProcedure even if we have the correct target in memory
        """
        kstrtab = self.reader.get_section_by_name("__ksymtab_strings")
        for exported_sym_name in kstrtab.data().split("\x00"):
            if exported_sym_name:
                self.get_symbol(exported_sym_name).is_export = True


register_backend('elfko', ELFKo)
