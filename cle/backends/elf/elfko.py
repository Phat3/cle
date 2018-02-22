import logging
from elftools.elf import elffile

from .elf import ELF
from .regions import ELFSection
from .. import register_backend
from .relocation import get_relocation
from .relocation.arm import R_ARM_CALL, R_ARM_PC24, R_ARM_JUMP24

l = logging.getLogger('cle.elfko')

class FakePltHeader:
    def __init__(self, sh_addr, sh_size):
        self.sh_offset = 0
        self.sh_flags = ELFSection.SHF_EXECINSTR | ELFSection.SHF_ALLOC
        self.sh_type =  ELFSection.SHT_NOBITS
        self.sh_size = sh_size 
        self.sh_addr = sh_addr
        self.sh_entsize = 32 
        self.sh_link = None
        self.sh_info = None
        self.sh_addralign = None

class ELFKo(ELF):
    """
    Loader class for ELF ko (Kernel modules) files.
    """

    def __init__(self, binary, **kwargs):
        self._registered_relocs_in_constants_pool = []
        super(ELFKo, self).__init__(binary, **kwargs)
        self._register_exports()

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


    def register_dependency(self):
        """
        Check if the module serves as a dependency of another module
        included in the analysis. If this is the case the module is added as
        dependent object.

        The onnly way to understand dependencies between kernel module is to
        know the order in which the module are loaded. Even in a real world
        scenario if you try to load modules in a different order than the correct
        one everything won't work (depmod takes care of this issues).

        It is possible to emulate this behaviour using this trick:
            - ASSUMPTIONS:
                - The order of the kernel module is known and the dependent Kmod
                  are listed inside the "force_load_libs" option from the one that
                  depends more on the others to the one that has no dependencies

            - Locate the currect Kmod (self) inside the shared_object dictionary
            - Put self as a dependency of all the Kmod listed before him in shared_object dict

        This is an over-extimation (it is not always true that a module serves as dependency of
        all the previous one) but at least is guaranteed that all the dependencies are
        satisfieed correctly.
        """
        shared_objects_list = self.loader.shared_objects.values()
        module_name = self.binary.split("/")[-1]
        module_order_number = self.loader.shared_objects.keys().index(module_name)
        for i in range(0,module_order_number):
            shared_objects_list[i].deps.append(module_name)


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
        if "__ksymtab_strings" in self.sections_map.keys():
            kstrtab = self.reader.get_section_by_name("__ksymtab_strings")
            for exported_sym_name in kstrtab.data().split("\x00"):
                if exported_sym_name:
                    self.get_symbol(exported_sym_name).is_export = True


    def _register_constants_pool_entries(self, readelf_reloc, readelf_destsec, symtab):
        """
        This function  tries to emulate the same functionality of the kernel while
        resolving symbols at loading time.
        (https://elixir.bootlin.com/linux/latest/source/arch/arm/kernel/module-plts.c#L139)

        In ARM since instruction are have a fixed length and one or more bytes are reserved
        for the opcode, it is not possible to jump, using a single instruction, in the entire memory space
        of the program.
        In order to make this possible we need to use a constant pool (pseudo-plt) that stores the
        only the real target addresses while the call is relocated with a pointer to the correct entry in that
        constant pool.

        :param readelf_reloc: Object of pyreadelf representing the section which hold the relocation
        :param readelf_destsec: Object of pyreadelf representing the destination section of the relocations
        :param symtab: symbol table that holds the symbols for those relocations

        :return :number of entry of the constant pool/plt (one for each call)

        TODO: Add missing check implented by the kernel in the same function
        """
        for reloc in readelf_reloc.iter_relocations():
            try:
                symbol = super(ELFKo, self).get_symbol(reloc.entry.r_info_sym, symtab)
                # reloc_type = get_relocation(self.arch.name, reloc.entry.r_info_type) 
                # if isinstance(reloc_type, R_ARM_CALL):
                #     import ipdb; ipdb.set_trace()
                angr_reloc = super(ELFKo, self)._make_reloc(reloc, symbol) 
                if isinstance(angr_reloc, R_ARM_CALL) and symbol.name not in self._registered_relocs_in_constants_pool: 
                    self._registered_relocs_in_constants_pool.append(symbol.name)
            # TODO: understand why sometimes when a symbol is created
            #       there is an out of bound error inside a list
            except:
                continue


    def _add_constants_pool(self):
        if len(self._registered_relocs_in_constants_pool):
            fake_header = FakePltHeader(1000, len(self._registered_relocs_in_constants_pool) * (self.arch.bits / 8))
            constants_pool = elffile.Section(fake_header, ".plt", self.memory)
            section = ELFSection(constants_pool)
            # Register sections first, process later - this is required by relocatable objects
            self.sections.append(section)
            self.sections_map[section.name] = section


register_backend('elfko', ELFKo)