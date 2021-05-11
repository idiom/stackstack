import ida_idaapi
import ida_kernwin
import idaapi
import ida_ua
import ida_diskio

import idc
import binascii
import os
import json
import logging

from stackstack.scan import YaraScanner
from stackstack.sue import SUE
from stackstack.utils import IdaHelpers, Update
from stackstack.patch import StringPatcher

BAD = [0xffffffff, 0xffffffffffffffff]
BAD_STR = ['ffffffff', 'ffffffffffffffff']

logging.basicConfig(format='stackstack:%(levelname)s:%(message)s', level=logging.DEBUG)


class StackStack(object):

    def __init__(self, loglevel=logging.DEBUG):
        self.logger = logging.getLogger()
        self.logger.setLevel(loglevel)

        self.last_bookmark = 0
        self.arch = IdaHelpers.get_arch()

    def find_end(self, offset):
        function_start = idc.get_func_attr(offset, idc.FUNCATTR_START)
        function_end = idc.get_func_attr(offset, idc.FUNCATTR_END)

        self.logger.debug('Function Start: %x' % function_start)
        self.logger.debug('Function End:   %x' % function_end)

        found_compare = False

        while offset <= function_end:
            ins = ida_ua.insn_t()
            idaapi.decode_insn(ins, offset)

            self.logger.debug('%x: %s' % (offset, idc.generate_disasm_line(offset, 0)))

            if ins.itype == idaapi.NN_jmp:
                return idc.next_head(offset, function_end)
            elif ins.itype == idaapi.NN_call:
                return idc.next_head(offset, function_end)
            elif ins.itype in [idaapi.NN_jmp, idaapi.NN_jnz, idaapi.NN_jb]:
                if found_compare:
                    return idc.next_head(offset, function_end)
            elif ins.itype == idaapi.NN_cmp:
                if idc.get_operand_type(offset, 0) == idc.o_reg \
                        and idc.get_operand_type(offset, 1) == idc.o_imm:
                    try:
                        self.logger.debug("Found compare..")
                        found_compare = True
                        string_length = int(idc.print_operand(offset, 1)) + 1
                        self.logger.debug("Setting String length: %d" % string_length)
                    except ValueError:
                        string_length = int(idc.print_operand(offset, 1)[:-1], 16) + 1
                        self.logger.debug("Setting String length: %d" % string_length)
                        # idc.set_color(cur_addr, CIC_ITEM, 0x00c3FF)
                        # idc.set_color(cur_addr, CIC_ITEM, 0x00C3FF)
                        # idc.set_color(cur_addr, CIC_ITEM, 0x00C3FF)
                        # print(hex(cur_addr), idc.generate_disasm_line(cur_addr, 0))
            offset = idc.next_head(offset, function_end)
        return 0

    def get_string_length(self, offset):
        function_end = idc.get_func_attr(offset, idc.FUNCATTR_END)
        self.logger.debug('Function End:   %x' % function_end)

        while offset <= function_end:
            ins = ida_ua.insn_t()
            idaapi.decode_insn(ins, offset)

            if ins.itype == idaapi.NN_jmp:
                return 0
            elif ins.itype == idaapi.NN_call:
                return 0
            elif ins.itype == idaapi.NN_cmp:
                if idc.get_operand_type(offset, 0) == idc.o_reg \
                        and idc.get_operand_type(offset, 1) == idc.o_imm:
                    try:
                        self.logger.debug("Found compare..")
                        return int(idc.print_operand(offset, 1)) + 1
                    except ValueError:
                        return int(idc.print_operand(offset, 1)[:-1], 16) + 1
            offset = idc.next_head(offset, function_end)

        return 0

    def detect_blocks(self, offset, trace_end=False):
        """
        Use ida basic blocks to detect last block etc.

        :param offset:
        :param trace_end:
        :return:
        """
        pass

    def backtrace_start(self, offset, trace_end=False):

        function_start = idc.get_func_attr(offset, idc.FUNCATTR_START)
        blob_start = 0
        last_mov = True

        # Back trace
        if offset <= function_start + 64:
            return function_start

        while offset >= function_start:
            ins = ida_ua.insn_t()

            idaapi.decode_insn(ins, offset)

            if ins.itype in [idaapi.NN_mov, idaapi.NN_sub, idaapi.NN_xor, idaapi.NN_lea]:
                if ins.itype == idaapi.NN_mov:
                    last_mov = True
                    if idc.get_operand_type(offset, 0) in [idaapi.o_mem, idaapi.o_reg] and \
                            idc.get_operand_type(offset, 1) in [idaapi.o_mem, idaapi.o_reg]:
                        blob_start = idc.next_head(offset)
                        break
                elif ins.itype == idaapi.NN_xor:
                    if idc.print_operand(offset, 0) != idc.print_operand(offset, 1):
                        blob_start = idc.next_head(offset)
                        break
                    last_mov = False
                elif ins.itype == idaapi.NN_sub:
                    if not last_mov:
                        blob_start = idc.next_head(offset)
                        break
                    last_mov = False
                elif ins.itype == idaapi.NN_lea:
                    last_mov = True

                offset = idc.prev_head(offset, function_start)
                blob_start = offset

                if offset <= function_start:
                    self.logger.debug("Error back-tracing ADVBLOB...Using function start")
                    blob_start = function_start
                    break
            else:
                blob_start = idc.next_head(offset)
                break

        if blob_start <= function_start + 64:
            blob_start = function_start

        self.logger.debug("BLOB Start: %x" % blob_start)
        self.logger.debug(idc.print_insn_mnem(blob_start))
        return blob_start

    def process_matches(self, matches, function_offset=0):
        """

        :param matches:
        :return:
        """

        # Disable this - this needs to be updated
        idc.warning("Not Implemented")
        return

class DecodeHandler(ida_kernwin.action_handler_t):
    """
        Handle hot key and mouse actions.

    """

    def __init__(self, patch=True, patch_type=1, patch_section=".stackstack", patch_section_size=0x1000, set_bookmarks=True):
        ida_kernwin.action_handler_t.__init__(self)
        self.scanner = YaraScanner()
        self.patch = patch
        self.logger = logging.getLogger()

        self.path_type = patch_type
        self.set_bookmarks = set_bookmarks

        # TODO: Move this, it inits before the file is loaded
        self.patcher = StringPatcher(patch_section, patch_section_size)

    def trace_bytes(self):
        start = idc.read_selection_start()
        end = idc.read_selection_end()

        if start == 0xffffffffffffffff:
            self.logger.error("Nothing selected")
            idc.warning("No instructions selected!")
            return

        self.logger.debug("Selection Start: 0x%x" % start)
        self.logger.debug("Selection End:   0x%x" % end)

        if not start or not end:
            idc.warning("Error: Range not selected")
            return

        semu = SUE(code_base=idaapi.get_imagebase(), loglevel=self.logger.level)
        semu.emulate_trace(start, end)

    def _determine_patch_type(self, start, end):
        """
        Determine if the code block should be patched.

        TODO: This should be expanded to better detect different implementations and return which patch type to use.

        :param start:
        :param end:
        :return:
        """

        self.logger.debug('End Param: %x' % end)
        ins = ida_ua.insn_t()
        idaapi.decode_insn(ins, idc.prev_head(end))
        idc.generate_disasm_line(idc.prev_head(end), 0)
        self.logger.debug("0x%x %s" % (end, idc.generate_disasm_line(idc.prev_head(end), 0)))
        if ins.itype == idaapi.NN_call:
            self.logger.debug("Ends in a call skip patching")
            return 0


    def _process(self, start, end, string_length=0):
        stacks = StackStack()
        self.logger.debug("_process->enter")

        if start >= end:
            self.logger.error("End block before start!")
            self.logger.debug("Start: %x" % start)
            self.logger.debug("End:   %x" % end)
            return

        if end:
            self.logger.debug("[*] Using ImageBase: %x" % idaapi.get_imagebase())
            semu = SUE(code_base=idaapi.get_imagebase())
            sresult = semu.deobfuscate_stack(start, end, string_length=string_length)

            self.logger.debug("...Complete....")

            if not sresult:
                self.logger.debug("No result data!")
                return

            self.logger.debug("-" * 16)
            for rk in sresult.keys():
                try:
                    self.logger.debug("%s: 0x%x" % (rk, sresult[rk]))
                except TypeError:
                    self.logger.debug("%s: %s" % (rk, sresult[rk]))
            self.logger.debug("-" * 16)

            decoded = sresult['data']

            if decoded:

                if self.set_bookmarks:
                    IdaHelpers.add_bookmark(start, decoded)

                if self.patch:
                    patch_type = self._determine_patch_type(start, end)
                    if patch_type == 0:
                        self.logger.info("Skipping Patch")
                        return

                    if self.path_type == 1:
                        self.patcher.patch_bytes(start, end, end, self.patcher.add_string_to_section(decoded))
                    else:
                        self.logger.info("patch_type_0 - Not Implemented")
                else:
                    IdaHelpers.add_comment(start, decoded)


    def update(self, ctx):
        """
            Required by action handler
        """
        return ida_kernwin.AST_ENABLE_ALWAYS

    def activate(self, ctx):
        if ctx.action == 'ssp_decode_selected':
            self.decode_selected()
        elif ctx.action == 'ssp_decode_current':
            self.decode_current()
        elif ctx.action == 'ssp_decode_func':
            self.decode_function()
        elif ctx.action == 'ssp_trace_selected':
            self.trace_bytes()
        else:
            self.logger.debug(ctx.cur_func)
            self.logger.debug("Not Supported")
            idc.warning("Not Implemented")
        return True

    def decode_function(self):

        advs = StackStack()
        offset = idaapi.get_item_head(idc.here())

        function_name = idc.get_func_name(offset)

        self.logger.debug("Processing: %s" % function_name)

        function_start = idc.get_func_attr(offset, idc.FUNCATTR_START)
        function_end = idc.get_func_attr(offset, idc.FUNCATTR_END)

        fdata = idc.get_bytes(function_start, function_end - function_start)

        refs = self.scanner.scan_function(fdata)

        if refs:
            self.logger.debug("Found [%d] Obfuscated Strings" % len(refs))

            advs.process_matches(refs, function_start)
        else:
            self.logger.debug("No code blocks found..")

    def decode_current(self):
        stacks = StackStack()

        offset = idaapi.get_item_head(idc.here())

        # TODO: Make this a configuration option to either use back trace or blocks
        start = stacks.backtrace_start(offset)

        self.logger.debug("Snippet Start: %x" % start)

        if start:
            end = stacks.find_end(start, 0)
            if end:
                string_length = stacks.get_string_length(start)
                self.logger.debug("Processing: start: %x, end: %x, string_length: %d" % (start, end, string_length))
                self._process(start, end, string_length=string_length)
            else:
                self.logger.error("Did not find end. Manually select instructions!")

        else:
            idc.warning("Decode Failed! Unable to get ADVBlock")

    def decode_selected(self):

        start = idc.read_selection_start()
        end = idc.read_selection_end()

        if start == 0xffffffffffffffff:
            self.logger.debug("Nothing selected")
            idc.warning("Nothing Selected!")
            return

        self.logger.debug("Selection Start: 0x%x" % start)
        self.logger.debug("Selection End:   0x%x" % end)

        if start:
            self._process(start, end)
        else:
            idc.warning("Selected Block ")

class ScanHandler(ida_kernwin.action_handler_t):

    def __init__(self, loglevel=logging.DEBUG):
        self.logger = logging.getLogger()
        self.logger.setLevel(loglevel)
        ida_kernwin.action_handler_t.__init__(self)
        self.scanner = YaraScanner()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

    def _scan_bin(self):
        scan_result = self.scanner.scan_functions()
        if not scan_result:
            self.logger.info("Found no suspect code blocks!")
            return

        self.logger.debug("-" * 16)
        self.logger.debug("Found %d suspect functions" % len(scan_result.keys()))
        for ref in scan_result:
            self.logger.debug('%s\t%d' % (ref, scan_result[ref]))
        self.logger.debug("-" * 16)

    def activate(self, ctx):
        if ctx.action == 'ssp_scan':
            self._scan_bin()
        else:
            self.logger.error("Unsupported scan option :: %s" % ctx.action)
            idc.warning("Unsupported Scan Option")
        return True

    def term(self):
        pass


class StackStackPlugin(ida_idaapi.plugin_t):

    flags = ida_idaapi.PLUGIN_KEEP

    comment = "StackStack simple emulation and tracing"
    help = "StackStack - simple emulation and tracing"
    wanted_name = "StackStack"
    wanted_hotkey = ""

    _PLUGIN_VERSION = 1.0

    def init(self):
        try:
            self.logger = logging.getLogger()
            self.config = self.load_configuration()
            try:
                self.logger.setLevel(logging._checkLevel(self.config['loglevel'].upper()))
            except ValueError:
                self.logger.setLevel(logging.DEBUG)
            self.logger.info("StackStack version: %d" % StackStackPlugin._PLUGIN_VERSION)
            version_check = Update.check_version(StackStackPlugin._PLUGIN_VERSION)
            if version_check > 0:
                idc.warning("StackStack version %s is now available for download." % version_check)
            self.logger.debug(self.config)

            self.actions = []
            self.define_actions()
            self.menus = Menus()
            self.menus.hook()
        except Exception as ex:
            self.logger.error('Error initializing StackStack %s' % ex)
            idc.warning('Error initializing StackStack %s' % ex)

        return ida_idaapi.PLUGIN_KEEP

    def load_configuration(self, config_name='stackstack.cfg', generate_default_config=True):
        path = ida_diskio.get_user_idadir()
        config_path = os.path.join(path, config_name)
        config_data = None

        if os.path.exists(config_path):
            with open(config_path, 'r') as inf:
                config_data = json.loads(inf.read())

        if config_data:
            return config_data

        if generate_default_config:
            config_data = self._generate_default_configuration()
            with open(config_path, 'w') as out:
                out.write(json.dumps(config_data))
        return config_data

    def _generate_default_configuration(self):
        return {
            'loglevel': 'DEBUG',
            'patch': True,
            'patch_type': 1,
            'patch_section_name': '.stackstack',
            'patch_section_size': 0x1000,
            'ext_yara_file': 'stackstack.yara',
            'bookmarks': True,
            'rename_func': False,
            'check_update': True
        }

    def _get_scan_actions(self):
        scanner = ScanHandler()
        return [
            ida_kernwin.action_desc_t(
                "ssp_scan",
                "Scan",
                scanner,
                "Shift-s",
                "Scan binary for functions with encrypted strings"
            )]

    def _get_decode_actions(self):
        decode = DecodeHandler()
        return [
            ida_kernwin.action_desc_t(
                "ssp_trace_selected",
                "Trace Selected",
                decode,
                "Trace the selected bytes."
            ),
            ida_kernwin.action_desc_t(
                "ssp_decode_selected",
                "Decode Selected",
                decode,
                "Decode the selected bytes."
            ),
            ida_kernwin.action_desc_t(
                "ssp_decode_current",
                "Decode Current",
                decode,
                "Shift-x",
                "Detect and decode the current obfuscated bytes."
            ),
            ida_kernwin.action_desc_t(
                "ssp_decode_all",
                "Decode All",
                decode,
                "Scan and decode all instances."
            ),
            ida_kernwin.action_desc_t(
                "ssp_decode_func",
                "Decode Function",
                decode,
                "Decode all instances in the current function."
            )
        ]

    def _get_util_actions(self):
        return [
            ida_kernwin.action_desc_t(
                "ssp_decode_func",
                "Decode Function",
                DecodeHandler(),
                "Decode all instances in the current function."
            )
        ]

    def define_actions(self):
        actions = []
        actions.extend(self._get_scan_actions())
        actions.extend(self._get_decode_actions())
        self.actions = actions
        for action_desc in actions:
            ida_kernwin.register_action(action_desc)

    def run(self, arg):
        """
        TODO: Add options UI here?
        :param arg:
        :return:
        """

        #scf = StackConfigForm()
        #scf.Show("StackStack Trace")
        pass


    def term(self):
        """
            Called on termination - unregister actions
        """
        if self.actions:
            for action_desc in self.actions:
                ida_kernwin.unregister_action(action_desc.name)

class Menus(ida_kernwin.UI_Hooks):
    """

    """
    def finish_populating_widget_popup(self, form, popup):
        '''
            This hooks the UI action when focus is on the disassembly or pseudocode page
        '''
        if ida_kernwin.get_widget_type(form) in [ida_kernwin.BWN_PSEUDOCODE]:
            ida_kernwin.attach_action_to_popup(form, popup, "ssp_decode_current", "StackStack/Decode/")

        if ida_kernwin.get_widget_type(form) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(form, popup, "ssp_decode_selected", "StackStack/Decode/")
            ida_kernwin.attach_action_to_popup(form, popup, "ssp_trace_selected", "StackStack/Trace/")

        if ida_kernwin.get_widget_type(form) in [ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_DISASM]:
            ida_kernwin.attach_action_to_popup(form, popup, "ssp_scan", "StackStack/")
            ida_kernwin.attach_action_to_popup(form, popup, "ssp_decode_all", "StackStack/Decode/")
            ida_kernwin.attach_action_to_popup(form, popup, "ssp_decode_func", "StackStack/Decode/")

def PLUGIN_ENTRY():
    return StackStackPlugin()