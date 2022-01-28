import ida_idaapi
import ida_kernwin
import idaapi
import ida_ua
import ida_diskio
import idautils

import idc
import os
import json
import logging

from stackstack.scan import YaraScanner
from stackstack.sue import SUE
from stackstack.utils import IdaHelpers, Update

BAD = [0xffffffff, 0xffffffffffffffff]


class StackStack(object):

    def __init__(self, logger):

        self.logger = logger

        self.last_bookmark = 0
        self.arch = IdaHelpers.get_arch()

    def find_end(self, offset):
        function_end = idc.get_func_attr(offset, idc.FUNCATTR_END)
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
            elif ins.itype == idaapi.NN_dec:
                if idc.get_operand_type(offset, 0) == idc.o_reg:
                    found_compare = True
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

    def _has_call(self, start, end):

        while start < end:
            ins = ida_ua.insn_t()
            idaapi.decode_insn(ins, start)
            if ins.itype == idaapi.NN_call:
                self.logger.debug("Found call at 0x%x..skipping using function start." % start)
                return True
            start = idc.next_head(start, end)
        return False

    def scan_reg_incremet(self, blob_start, offset):
        """

        Check if the block uses a register to increment the counter. Some samples will have something similar to

        <snip>
        xor     r15d, r15d
        <snip>
        lea     r12d, [r15+1]
        <snip>
        add     rax, r12

        :return: None if not found or identified register
        """

        function_start = idc.get_func_attr(offset, idc.FUNCATTR_START)
        cursor = 0

        found_compare = False
        found_operand = False
        cmp_reg = None
        inc_reg = None
        while offset >= blob_start:
            cursor += 1
            ins = ida_ua.insn_t()
            idaapi.decode_insn(ins, offset)

            self.logger.debug('%x: %s' % (offset, idc.generate_disasm_line(offset, 0)))

            if not found_compare:
                if ins.itype == idaapi.NN_cmp:
                    if idc.get_operand_type(offset, 0) == idc.o_reg:
                        cmp_reg = idc.get_operand_value(offset, 0)
                        found_compare = True

            if found_compare:
                if ins.itype == idaapi.NN_add:
                    if idc.get_operand_type(offset, 0) == idc.o_reg \
                            and idc.get_operand_value(offset, 0) == cmp_reg \
                            and idc.get_operand_type(offset, 1) == idc.o_reg:
                                    #inc_reg = idc.get_operand_value(offset, 1)
                                    inc_reg = idc.print_operand(offset, 1)
                                    return inc_reg
                                    #cmp_reg = idc.get_operand_value(offset, 0)

                elif ins.itype == idaapi.NN_add:
                    if found_operand:
                        if idc.get_operand_type(offset, 0) == idc.o_reg and idc.get_operand_value(offset, 0) == cmp_reg:
                            # first op is a reg and matches the expected
                            if idc.get_operand_type(offset, 1) == idc.o_reg:
                                inc_reg = idc.print_operand(offset, 1)
                                self.logger.debug("Found inc reg :: %s" % inc_reg)
                                return inc_reg
                                # second op is a reg

            offset = idc.prev_head(offset, function_start)
        return None

    def backtrace_start(self, offset, max_instructions=1024):
        """
        From the current offset - backtrace and find the best instruction to start emulation.

        :param offset:
        :param max_instructions: The maximum number of instructions to backtrace
        :return:
        """
        function_start = idc.get_func_attr(offset, idc.FUNCATTR_START)
        blob_start = 0
        last_mov_or_alt = True

        trace_instruction_types = [idaapi.NN_mov,
                                   idaapi.NN_sub,
                                   idaapi.NN_xor,
                                   idaapi.NN_lea,
                                   idaapi.NN_add,
                                   idaapi.NN_inc,
                                   idaapi.NN_movupd,
                                   idaapi.NN_movups,
                                   idaapi.NN_movaps,
                                   idaapi.NN_movapd,]

        # Back trace
        if offset <= function_start + 64:
            """
            Note this can cause issues. If there is a call or other that is expected to have
            initialized data. Do a quick check first before returning the function start                         
            """

            if not self._has_call(function_start, offset):
                return function_start
        icount = 0
        while offset >= function_start:
            icount += 1

            if icount > max_instructions:
                return 0

            ins = ida_ua.insn_t()

            idaapi.decode_insn(ins, offset)
            self.logger.debug("0x%x %s" % (offset, idc.generate_disasm_line(idc.prev_head(offset), 0)))

            if ins.itype in trace_instruction_types:
                if ins.itype in [idaapi.NN_mov]:
                    last_mov_or_alt = True
                elif ins.itype == idaapi.NN_xor:
                    if idc.print_operand(offset, 0) != idc.print_operand(offset, 1):
                        if idc.get_operand_type(offset, 1) != idaapi.o_imm:
                            blob_start = idc.next_head(offset)
                            break
                        else:
                            last_mov_or_alt = True
                    else:
                        last_mov_or_alt = False
                elif ins.itype == idaapi.NN_sub:
                    if not last_mov_or_alt:
                        blob_start = idc.next_head(offset)
                        break
                    last_mov_or_alt = False
                elif ins.itype in [idaapi.NN_lea, idaapi.NN_inc, idaapi.NN_add]:
                    last_mov_or_alt = True

                blob_start = offset

                if offset <= function_start:
                    self.logger.debug("Error back-tracing ADVBLOB...Using function start")
                    blob_start = function_start
                    break

            else:
                blob_start = idc.next_head(offset)
                break

            offset = idc.prev_head(offset)

        if blob_start <= function_start + 64:
            if not self._has_call(function_start, blob_start):
                blob_start = function_start

        self.logger.debug("BLOB Start: %x" % blob_start)
        self.logger.debug(idc.print_insn_mnem(blob_start))
        return blob_start


class DecodeHandler(ida_kernwin.action_handler_t):
    """
        Handle hot key and mouse actions.

    """

    def __init__(self, logger, set_bookmarks=True, has_hexrays=False):
        ida_kernwin.action_handler_t.__init__(self)
        self.scanner = YaraScanner(logger)
        self.logger = logger
        self.has_hexrays = has_hexrays

        self.set_bookmarks = set_bookmarks
        self.mode = int(IdaHelpers.get_arch()/8)
        self.stacks = StackStack(logger)

    def trace_bytes(self):
        start = idc.read_selection_start()
        end = idc.read_selection_end()

        if start in BAD:
            self.logger.error("Nothing selected")
            idc.warning("No instructions selected!")
            return

        self.logger.debug("Selection Start: 0x%x" % start)
        self.logger.debug("Selection End:   0x%x" % end)

        if not start or not end:
            idc.warning("Error: Range not selected")
            return

    def _identify_impl_type(self, start, end):
        """
        Identify the implementation type.

        0 - func - string is decrypted in a call to a function. Offset is returned in eax
        1 - inline1 -

        TODO: This should be expanded to better detect different implementations

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
            self.logger.debug("Ends in a call")
            return 0

    def _process(self, start, end, string_length=0):
        self.logger.debug("_process->enter")

        if start >= end:
            self.logger.error("End block before start!")
            self.logger.debug("Start: %x" % start)
            self.logger.debug("End:   %x" % end)
            return

        if end:
            ireg = self.stacks.scan_reg_incremet(start, end)
            iregs = []
            if ireg:
                self.logger.debug("[*] Initializing [%s] to 1" % ireg)
                iregs.append((ireg, 1))

            self.logger.debug("[*] Using ImageBase: %x" % idaapi.get_imagebase())

            impl_type = self._identify_impl_type(start, end)

            semu = SUE(code_base=idaapi.get_imagebase(), mode=self.mode, logger=self.logger)

            sresult = semu.deobfuscate_stack(start, end, string_length=string_length, impl_type=impl_type, init_regs=iregs)

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
                IdaHelpers.add_comment(start, decoded, hexrays=self.has_hexrays)
                return decoded

    def process_matches(self, matches, function_start):
        """

        :param matches:
        :return:
        """

        if not matches:
            return

        # stacks = StackStack(self.logger)

        last_start = 0
        last_end = 0
        decoded_strings = []
        deocded_offsets = []
        for match in matches:
            try:
                match_offset = function_start + match
                self.logger.debug("Processing match offset: %x" % match_offset)
                block_start = self.stacks.backtrace_start(match_offset)
                if not block_start:
                    self.logger.error("Could not find block start for %x .. skipping" % match_offset)
                    continue

                block_end = self.stacks.find_end(block_start)
                if not block_end:
                    self.logger.error("Could not find block end for %x .. skipping" % match_offset)
                    continue

                if last_end == 0 == last_start:
                    last_end = block_end
                    last_start = block_start
                else:
                    if last_start < match_offset < last_end:
                        self.logger.debug("Skipping offset [%x]" % match_offset)
                        continue


                string_length = self.stacks.get_string_length(block_start)
                self.logger.debug("Processing: start: %x, end: %x, string_length: %d" % (block_start, block_end, string_length))
                decoded = self._process(block_start, block_end, string_length=string_length)
                if decoded:
                    if not block_start in deocded_offsets:
                        decoded_strings.append((block_start, decoded))
                        deocded_offsets.append(block_start)

                self.logger.debug("Using start of: %x" % block_start)
            except Exception as ex:
                self.logger.error("Error processing block: %s" % ex)

        return decoded_strings

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
        elif ctx.action == 'ssp_decode_all':
            self.decode_all()
        else:
            self.logger.debug(ctx.cur_func)
            self.logger.debug("Not Supported")
            idc.warning("Not Implemented")
        return True

    def decode_function(self):

        # advs = StackStack(self.logger)
        offset = idaapi.get_item_head(idc.here())

        function_name = idc.get_func_name(offset)

        self.logger.debug("Processing: %s" % function_name)

        function_start = idc.get_func_attr(offset, idc.FUNCATTR_START)
        function_end = idc.get_func_attr(offset, idc.FUNCATTR_END)

        fdata = idc.get_bytes(function_start, function_end - function_start)

        refs = self.scanner.scan_function(fdata)

        if refs:
            self.logger.debug("Found [%d] Obfuscated Strings" % len(refs))

            decoded_strings = self.process_matches(refs, function_start)
            if decoded_strings:
                # TODO: Add this to a UI Pop-up
                print("--- Decoded Function Strings ---")
                for o, s in decoded_strings:
                    print(" %x: %s" % (o, s))

        else:
            self.logger.debug("No code blocks found..")

    def decode_all(self):
        try:
            # ss = StackStack(self.logger)
            decoded_strings = []
            for func_entry in idautils.Functions():
                if idc.get_func_attr(func_entry, idc.FUNCATTR_FLAGS) & idc.FUNC_LIB:
                    self.logger.debug("Skipping lib function %s" % idc.get_func_name(func_entry))
                    continue

                fdata = idc.get_bytes(func_entry, idc.get_func_attr(func_entry, idc.FUNCATTR_END) - func_entry)
                refs = self.scanner.scan_function(fdata)
                if refs:
                    self.logger.debug("Found [%d] Obfuscated Strings" % len(refs))
                    decoded_strings.extend(self.process_matches(refs, func_entry))

            if decoded_strings:
                # TODO: Add this to a UI Pop-up
                print("--- Decoded Function Strings ---")
                for o, s in decoded_strings:
                    print(" %x: %s" % (o, s))
        except Exception as ex:
            self.logger.error("Error processing file: %s" % ex)

    def decode_current(self):
        # stacks = StackStack(self.logger)

        offset = idaapi.get_item_head(idc.here())
        self.logger.debug("Starting scan at offset: %x" % offset)

        # TODO: Make this a configuration option to either use back trace or blocks
        start = self.stacks.backtrace_start(offset)

        self.logger.debug("Snippet Start: %x" % start)

        if start:
            end = self.stacks.find_end(start)
            if end:
                string_length = self.stacks.get_string_length(start)
                self.logger.debug("Processing: start: %x, end: %x, string_length: %d" % (start, end, string_length))
                self._process(start, end, string_length=string_length)
            else:
                self.logger.error("Did not find end. Manually select instructions!")

        else:
            idc.warning("Decode Failed! Unable to get ADVBlock")

    def decode_selected(self):

        start = idc.read_selection_start()
        end = idc.read_selection_end()

        if start in BAD:
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

    def __init__(self, logger):
        self.logger = logger
        ida_kernwin.action_handler_t.__init__(self)
        self.scanner = YaraScanner(logger)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

    def _scan_bin(self):
        self.logger.info("Scanning file...")
        scan_result = self.scanner.scan_functions()
        self.logger.info("Scan complete...")
        if not scan_result:
            self.logger.error("Found no suspect code blocks!")
            return

        self.logger.info("-" * 16)
        self.logger.info("Found %d suspect functions" % len(scan_result.keys()))
        for ref in scan_result:
            self.logger.info('%s\t%d' % (ref, scan_result[ref]))
        self.logger.info("-" * 16)

    def activate(self, ctx):
        if ctx.action == 'ssp_scan':
            self._scan_bin()
        else:
            self.logger.error("Unsupported scan option :: %s" % ctx.action)
            idc.warning("Unsupported Scan Option")
        return True

    def term(self):
        pass


class StackStackConfig(object):
    pass


class StackStackPlugin(ida_idaapi.plugin_t):

    flags = ida_idaapi.PLUGIN_KEEP

    comment = "StackStack simple emulation and tracing"
    help = "StackStack - simple emulation and tracing"
    wanted_name = "StackStack"
    wanted_hotkey = ""

    _version = 1.06

    def init(self):
        try:
            self.config = self.load_configuration()
            try:
                self.logger = self._init_logger(logging._checkLevel(self.config['loglevel'].upper()))
            except ValueError:
                self.logger = self._init_logger(self.logger.setLevel(logging.DEBUG))

            # TODO: Remove
            self.logger.setLevel(logging.DEBUG)

            self.logger.info("StackStack version: %s" % StackStackPlugin._version)

            if self.config['check_update']:
                version_check = Update.check_version(StackStackPlugin._version)
                if version_check > 0:
                    idc.warning("StackStack version %s is now available for download." % version_check)

            self.has_hexrays = IdaHelpers.has_decompiler()

            self.actions = []
            self.define_actions()
            self.menus = Menus()
            self.menus.hook()
        except Exception as ex:
            self.logger.error('Error initializing StackStack %s' % ex)
            idc.warning('Error initializing StackStack %s' % ex)

        return ida_idaapi.PLUGIN_KEEP

    def _init_logger(self, loglevel, name='stackstack'):
        """
        Initialize Logger

        :param loglevel: Log Level to use
        :param name: Log name
        :return:
        """
        # logging.basicConfig()
        # logging.root.setLevel(logging.NOTSET)

        logger = logging.getLogger(name)
        # logger.setLevel(loglevel)
        logger.setLevel(loglevel)

        log_stream = logging.StreamHandler()
        formatter = logging.Formatter('stackstack:%(levelname)s:%(message)s')
        log_stream.setFormatter(formatter)
        logger.addHandler(log_stream)
        return logger

    def load_configuration(self, config_name='stackstack.cfg', generate_default_config=True):
        path = ida_diskio.get_user_idadir()
        config_path = os.path.join(path, config_name)
        config_data = None

        if os.path.exists(config_path):
            with open(config_path, 'r') as inf:
                config_data = json.loads(inf.read())

        if config_data:
            def_config = self._generate_default_configuration()
            missing_options = False
            for key in def_config.keys():
                # iterate through the default config keys and add any missing config entries.
                try:
                    config_data[key]
                except KeyError:
                    config_data[key] = def_config[key]
                    missing_options = True
            if missing_options:
                with open(config_path, 'w') as out:
                    out.write(json.dumps(config_data))
            return config_data

        if generate_default_config:
            config_data = self._generate_default_configuration()
            with open(config_path, 'w') as out:
                out.write(json.dumps(config_data))
        return config_data

    def _generate_default_configuration(self):
        return {
            'loglevel': 'DEBUG',
            'ext_yara_file': 'stackstack.yara',
            'bookmarks': True,
            'rename_func': False,
            'check_update': False
        }

    def _get_scan_actions(self):
        scanner = ScanHandler(self.logger)
        return [
            ida_kernwin.action_desc_t(
                "ssp_scan",
                "Scan",
                scanner,
                "Shift-s",
                "Scan binary for functions with encrypted strings"
            )]

    def _get_decode_actions(self):
        decode = DecodeHandler(self.logger, has_hexrays=self.has_hexrays)
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
                DecodeHandler(has_hexrays=self.has_hexrays),
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
        print('-------------------------------------')
        print('running\n\n\n\n\n\n\n\n\n')
        print('-------------------------------------')
        pass

    def term(self):
        if self.actions:
            for action_desc in self.actions:
                ida_kernwin.unregister_action(action_desc.name)


class Menus(ida_kernwin.UI_Hooks):

    def finish_populating_widget_popup(self, form, popup):

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
