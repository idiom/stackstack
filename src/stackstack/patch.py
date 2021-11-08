import ida_auto
import ida_hexrays
import idc
import idaapi
import ida_ua
import ida_nalt
import ida_bytes
import logging
from enum import Enum

from keystone.keystone import *
from capstone import *

from stackstack.utils import IdaHelpers


class PatchTypes(Enum):
    Unsupported = 0
    Generic = 1
    CallRet = 2


class PatchException(Exception):
    pass


class StringPatcher(object):

    def __init__(self, name='.stackstack', size=0x1000, offset=0, decompile=True, loglevel=logging.DEBUG):
        self.name = name

        self.logger = logging.getLogger('stackstack')
        self.logger.setLevel(loglevel)
        self.decompile = decompile

        self.size = size
        self.offset = offset
        # self.last_patch_offset = 0
        self.string_cache = {}
        self.patchable_instructions = [idaapi.NN_mov, idaapi.NN_lea]


    def _init_segment(self):
        if not idaapi.get_segm_by_name(self.name):
            IdaHelpers.add_section(self.offset, self.name, bitness=IdaHelpers.get_bitness(), size=self.size, base=0)
        return idaapi.get_segm_by_name(self.name)

    def patch_func_return(self, string_offset):
        pass

    def generate_patch_bytes(self, code_offset, string_offset):
        """

        Generate the patch bytes using Keystone engine.

        I've done some testing with .Assemble and .AssembleLine, but it doesn't appear
        to be fully supported - supporting a set number of instructions.

        .Assemble has a bug where it will always use 32bit.

        .Assemble -> ._Assemble -> .AssembleLine

        In ._Assemble, the segments bitness is passed to the param use32


        :param code_offset:
        :param string_offset:
        :return:
        """
        mode = CS_MODE_64
        ksmode = KS_MODE_64
        if IdaHelpers.get_arch() < 64:
            mode = CS_MODE_32
            ksmode = KS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        cdata = idaapi.get_bytes(code_offset, (idaapi.get_item_size(code_offset)))

        #
        # TODO: Fix this up, make it configurable?.
        #
        if mode > 4:
            code = "push r12;lea r12,cs:[rip+%d];mov [%s, r12; pop r12"
            ripoffset = string_offset - (code_offset + 2)
            self.logger.debug("RIP Offset: %x" % ripoffset)

            for instr in md.disasm(cdata, code_offset):
                code = code % (ripoffset, instr.op_str.split(",")[0].split(" [")[1])
                break
        else:
            return b''

        self.logger.debug("Patch offset: %x" % code_offset)
        self.logger.debug("string offset: %x" % string_offset)

        try:
            # Initialize engine
            ks = Ks(KS_ARCH_X86, ksmode)
            bytecode, count = ks.asm(code)
            if count > 0:
                return bytes(bytecode)
            self.logger.error("Error no bytes returned after assembling.")
        except KsError as e:
            self.logger.error("Error assembling patch: %s" % e)
        return b''

    def find_instruction_to_patch(self, start, end):
        """
        Based on the code block figure out which var/offset is most referenced.

        Generally we should see a byte push to X, then a loop which iterates through the bytes using the var + an offset

        :param start:
        :param end:
        :return:
        """

        dmap = {}
        pref = None
        max_ref = 0
        block_start = start
        offset = 0
        while start <= end:
            if idc.get_operand_type(start, 0) == idaapi.o_displ:
                op = idc.print_operand(start, 0)
                try:
                    val = op.rsplit('+', 1)[1]
                except IndexError:
                    val = op.rsplit('-', 1)[1]
                try:
                    dmap[val] += 1
                except KeyError:
                    dmap[val] = 1

                if dmap[val] > max_ref:
                    max_ref = dmap[val]
                    pref = val
            start = idc.next_head(start, end)

        if not pref:
            return 0

        start = block_start

        while start <= end:
            if idc.get_operand_type(start, 0) == idaapi.o_displ:
                if pref in idc.generate_disasm_line(start, 0):
                    offset = start
                    break
            start = idc.next_head(start, end)

        return offset

    def _existing_string_offset(self, nstring):
        """
        Check if the string already exists and if it does return the offset.

        :param nstring: The string
        :return: Offset to string or 0
        """
        segment = self._init_segment()
        cursor = segment.start_ea
        while cursor < segment.end_ea:
            string_length = ida_bytes.get_max_strlit_length(cursor, ida_nalt.STRTYPE_C)
            if string_length == 0:
                if idaapi.get_byte(cursor) == 0xff:
                    return 0
                cursor += 1
                continue
            data = ida_bytes.get_strlit_contents(cursor, string_length, ida_nalt.STRTYPE_C)
            if nstring == data.decode():
                self.logger.debug(" Using reference [0x%x] for %s" % (cursor, data.decode()))
                return cursor - 8
            cursor += string_length
        return 0

    def add_string_to_section(self, data):
        segment = self._init_segment()

        offset = self._existing_string_offset(data)
        self.logger.debug("Offset for string is: %x" % offset)
        if offset > 0:
            return offset

        if not data[-1] == '\x00':
            data += '\x00'

        align = IdaHelpers.SegmentAlignMap[segment.align]
        self.logger.debug("Using alignment of %d" % align)

        ea = segment.start_ea

        offset = 0
        while ea < segment.end_ea:
            if idaapi.get_byte(ea) == 0xff:
                offset = ea
                break
            ea += 1

        if not offset:
            raise PatchException("Unable to find space in section")

        if align > 0:
            align_off = (align - (offset & (align - 1))) & (align - 1)
            padding = "\x00" * ((align - ((offset + len(data)) & (align - 1))) & (align - 1))
            data += padding
            self.logger.debug("Align: %x" % align_off)
            offset += align_off
            self.logger.debug("Aligned offset: %x" % offset)
        idaapi.patch_bytes(offset, str.encode(data))
        idc.create_strlit(offset, offset + len(data))

        return offset - 8

    def patch_bytes(self, start, end, patch_offset, string_offset):
        """

        :param start:
        :param end:
        :param patch_offset:
        :param string_offset:
        :return:
        """

        doff = self.find_instruction_to_patch(start, end)
        if doff > 0:
            patch_offset = doff

        # Check that start is before end
        if start > end:
            self.logger.error("Invalid patch start or end! Start: %x, End: %x" % (start, end))
            raise PatchException("Invalid patch start or end")

        if not string_offset or not patch_offset:
            self.logger.error("No string or patch offset provided patch_offset: %x, string_offset: %x" %
                              (patch_offset, string_offset))
            raise PatchException("No string or patch offset provided")

        ins = ida_ua.insn_t()
        idaapi.decode_insn(ins, patch_offset)

        self.logger.debug("Checking if offset is patchable...")
        if ins.itype in self.patchable_instructions:
            self.logger.debug("OK")
            bytecode = self.generate_patch_bytes(patch_offset, string_offset)

            if len(bytecode) == 0:
                self.logger.error("Error generating patch..skipping")
                return False

            # line_size = idaapi.get_item_size(patch_offset)

            patch_data = b"\x90" * ((end - patch_offset) - len(bytecode))
            patch_data = bytecode + patch_data
            self.logger.debug("Patching bytes...")
            self.logger.debug("Patch Size: %d" % len(patch_data))
            self.logger.debug("Patch Offset: %x" % patch_offset)
            self.logger.debug("String Offset: %x" % string_offset)
            idaapi.patch_bytes(patch_offset, patch_data)
            self.logger.debug("Ok...Analyzing")
            ida_bytes.add_hidden_range(patch_offset+len(bytecode), end, '[StackStack Patch]', '', '', 0x887766)

            # Note: Undefine then mark the range as code..
            # undefine the bytes
            ida_bytes.del_items(patch_offset, ida_bytes.DELIT_SIMPLE, len(patch_data))

            # Mark the range as code
            idc.auto_mark_range(patch_offset+2, patch_offset+len(bytecode), idc.AU_CODE)
            if self.decompile:
                try:
                    idaapi.decompile(start)
                except ida_hexrays.DecompilationFailure as df:
                    self.logger.error(df)
                    self.decompile = False
            # Do I need this...ffs this API
            ida_auto.auto_wait()
            self.logger.debug("Patch complete")
            return True
