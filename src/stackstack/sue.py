from unicorn import *
from unicorn.x86_const import *
from enum import Enum

import idaapi
import idautils
import idc
import ida_ua
import logging


class EmulationTimeout(Exception):
    pass


class IdaUnicornMap(Enum):
    pass


class SUE(object):
    """
    An emulator named SUE (Simple Unicorn Emulator)

    """

    RegisterMap = {
        "ecx": UC_X86_REG_ECX,
        "edx": UC_X86_REG_EDX,
        "ebx": UC_X86_REG_EBX,
        "eax": UC_X86_REG_EAX,
        "esi": UC_X86_REG_ESI,
        "edi": UC_X86_REG_EDI,
        "ebp": UC_X86_REG_EBP,
        "esp": UC_X86_REG_ESP,
        "eip": UC_X86_REG_EIP,
        "r8d": UC_X86_REG_R8D,
        "r9d": UC_X86_REG_R9D,
        "r10d": UC_X86_REG_R10D,
        "r11d": UC_X86_REG_R11D,
        "r12d": UC_X86_REG_R12D,
        "r13d": UC_X86_REG_R13D,
        "r14d": UC_X86_REG_R14D,
        "r15d": UC_X86_REG_R15D,
        "r8w": UC_X86_REG_R8W,
        "r9w": UC_X86_REG_R9W,
        "r10w": UC_X86_REG_R10W,
        "r11w": UC_X86_REG_R11W,
        "r12w": UC_X86_REG_R12W,
        "r13w": UC_X86_REG_R13W,
        "r14w": UC_X86_REG_R14W,
        "r15w": UC_X86_REG_R15W,
        "r8b": UC_X86_REG_R8B,
        "r9b": UC_X86_REG_R9B,
        "r10b": UC_X86_REG_R10B,
        "r11b": UC_X86_REG_R11B,
        "r12b": UC_X86_REG_R12B,
        "r13b": UC_X86_REG_R13B,
        "r14b": UC_X86_REG_R14B,
        "r15b": UC_X86_REG_R15B,
        "rip": UC_X86_REG_RIP,
        "rax": UC_X86_REG_RAX,
        "rbx": UC_X86_REG_RBX,
        "rcx": UC_X86_REG_RCX,
        "rdx": UC_X86_REG_RDX,
        "rsi": UC_X86_REG_RSI,
        "rdi": UC_X86_REG_RDI,
        "rbp": UC_X86_REG_RBP,
        "rsp": UC_X86_REG_RSP,
        "r8": UC_X86_REG_R8,
        "r9": UC_X86_REG_R9,
        "r10": UC_X86_REG_R10,
        "r11": UC_X86_REG_R11,
        "r12": UC_X86_REG_R12,
        "r13": UC_X86_REG_R13,
        "r14": UC_X86_REG_R14,
        "r15": UC_X86_REG_R15,
        "xmm0": UC_X86_REG_XMM0,
        "xmm1": UC_X86_REG_XMM1,
        "xmm2": UC_X86_REG_XMM2,
        "xmm3": UC_X86_REG_XMM3
    }

    MemoryAccessLookup = {
        UC_MEM_READ: "UC_MEM_READ",
        UC_MEM_FETCH: "UC_MEM_FETCH",
        UC_MEM_READ_UNMAPPED: "UC_MEM_READ_UNMAPPED",
        UC_MEM_WRITE_UNMAPPED: "UC_MEM_WRITE_UNMAPPED",
        UC_MEM_FETCH_UNMAPPED: "UC_MEM_FETCH_UNMAPPED",
        UC_MEM_WRITE_PROT: "UC_MEM_WRITE_PROT",
        UC_MEM_FETCH_PROT: "UC_MEM_FETCH_PROT",
        UC_MEM_READ_AFTER: "UC_MEM_READ_AFTER"
    }

    def __init__(self, code_base=0x18000000, stack_base=0xA0000000, stack_size=0x10000, sg=0x28, loglevel=logging.DEBUG,
                 trace=False):
        """
        What properties are really useful here?

        :param code_base:
        :param stack_base:
        :param stack_size:
        :param sg:
        :param debug:
        :param trace:
        """
        self.logger = logging.getLogger()
        self.logger.setLevel(loglevel)

        self.stack_data = ""
        self.code_base = code_base
        self.sg = sg
        self.debug = debug
        self.trace = trace
        self.stack_fw = 0
        self.read_switch = False
        self.decoded_stack = ""

        # Remove?
        self.stack_grow = True

        self.write_switch = False
        self.stack_base = stack_base
        self.stack_size = stack_size
        self.last_write_address = 0
        self.first_write_address = 0

    def _map_full_file(self, mu):
        for seg in idautils.Segments():
            data = None
            cur_seg = idaapi.getseg(seg)
            size = cur_seg.end_ea - cur_seg.start_ea
            if size > 0:
                data = idc.get_bytes(cur_seg.start_ea, size)
                if data is None:
                    continue
            mu.mem_write(cur_seg.start_ea, data)

    def _setup_emulator(self, code_base):
        arch = UC_ARCH_X86
        mode = UC_MODE_32
        mu = None

        if idaapi.get_inf_structure().is_64bit():
            mode = UC_MODE_64

        mu = Uc(arch, mode)

        end_address = self._get_end_address()

        # align
        size = end_address - code_base + (0x1000 - end_address % 0x1000)
        mu.mem_map(self.code_base, size)

        return mu

    def _get_end_address(self):
        end_address = 0

        for segment in idautils.Segments():
            if idaapi.getseg(segment).end_ea > end_address:
                end_address = idaapi.getseg(segment).end_ea
        return end_address

    def hook_mem_access(self, uc, access, address, size, value, user_data):
        """


        """
        if access == UC_MEM_WRITE:
            if self.trace:
                self.logger.debug("Memory Write at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))

            try:
                # First Write Address
                self.write_switch = True

                if size == 1:
                    if self.read_switch:
                        if not self.first_write_address:
                            self.first_write_address = address
                        self.decoded_stack += chr(value)
                    self.last_write_address = address

            except Exception as ex:
                self.logger.error("Memory Hook exception: %s" % ex)

        else:
            if size == 1:
                if self.stack_fw == 0:
                    if self.write_switch:
                        self.stack_fw = address

                if self.stack_fw > 0:
                    self.read_switch = True

            if self.trace:
                pass
                # self._debug_log("Memory READ at 0x%x, data size = %u" % (address, size))

    def hook_code(self, mu, address, size, user_data):
        if self.trace:
            self.logger.info('TRACE: 0x%x, instruction size = 0x%x' % (address, size))

    def hook_patch_inc(self, mu, address, size, user_data):
        if self.trace:
            self.logger.info('TRACE: 0x%x, instruction size = 0x%x' % (address, size))
            # rip = mu.reg_read(UC_X86_REG_RIP)
            # self._debug_log("TRACE: RIP is 0x%x" % rip)

        iobj = ida_ua.insn_t()
        idaapi.decode_insn(iobj, address)
        if iobj.itype == idaapi.NN_add:
            self.logger.debug('Found Add Instruction')
            if iobj.Op1.type == idaapi.o_reg:
                self.logger.debug('Op1 is reg')
                if iobj.Op2.type == idaapi.o_reg:
                    self.logger.debug('Op2 is reg')
                    reg = idc.print_operand(address, 1)
                    self.logger.debug('Register: %s' % reg)
                    val = mu.reg_read(self.RegisterMap[reg])
                    self.logger.debug('Register Value: %x' % val)
                    if val == 0:
                        self.logger.debug('Setting %s to 1' % reg)
                        mu.reg_write(self.RegisterMap[reg], 1)

    def trace_code(self, mu, address, size, user_data):
        """
        Hook to emit trace information to ida
        :param mu:
        :param address:
        :param size:
        :param user_data:
        :return:
        """
        comment = ""
        for x in range(2):
            if idc.get_operand_type(address, x) == idaapi.o_reg:
                try:
                    if comment:
                        comment += ", "
                    reg_data = mu.reg_read(self.RegisterMap[idc.print_operand(address, x)])
                    comment += "%s: 0x%x" % (idc.print_operand(address, x), reg_data)
                except KeyError:

                    pass
        if comment:
            idc.set_cmt(address, comment, 0)
        self.logger.debug(comment)

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        rip = uc.reg_read(UC_X86_REG_RIP)

        if access == UC_MEM_WRITE:
            self.logger.debug(
                "Invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, rip, size, value))
        else:
            self.logger.debug(
                "Invalid %s of 0x%x at 0x%X, data size = %u" % (SUE.MemoryAccessLookup[access], address, rip, size))

        return False

    def emulate(self, start_address, end_address, hooks, timeout=1):
        """

        :param start_address:
        :param end_address:
        :param hooks:
        :param timeout:
        :return:
        """
        mu = self._setup_emulator(self.code_base)
        self._map_full_file(mu)

        for reg in SUE.RegisterMap.values():
            mu.reg_write(reg, 0)

        # Setup stack
        mu.mem_map(self.stack_base, self.stack_size)
        mu.reg_write(UC_X86_REG_ESP, self.stack_base + 0x1000)
        mu.reg_write(UC_X86_REG_EBP, self.stack_base + 0x1000)

        # Add hooks
        if hooks:
            for hook in hooks:
                mu.hook_add(hook[0], hook[1])

        # self._debug_log("Code Length %d" % len(byte_stream))
        self.logger.debug("Starting Emulation")

        # emulate code
        mu.emu_start(start_address, end_address, timeout=timeout * UC_SECOND_SCALE)

        if timeout > 0:
            rip = mu.reg_read(UC_X86_REG_RIP)
            self.logger.debug("RIP: %x" % rip)
            self.logger.debug("Expected end: %x" % end_address)
            if end_address != mu.reg_read(UC_X86_REG_RIP):
                raise EmulationTimeout()

        self.logger.debug("Emulation Complete..")

        return mu

    def emulate_trace(self, start_address, end_address):
        hooks = [
            (UC_HOOK_CODE, self.trace_code)
        ]
        self.logger.debug("Starting Trace")
        mu = self.emulate(start_address, end_address, hooks)
        self.logger.debug("Trace Complete")

        for reg in self.RegisterMap.keys():
            try:
                self.logger.info("%s: %x" % (reg, mu.reg_read(self.RegisterMap[reg])))
            except Exception as ex:
                self.logger.error("Error reading register :: %s" % reg)
                self.logger.error("Error: %s" % ex)

    def _get_func_decoded(self, mu, mode):
        result = {}
        data = ''
        reg = 'rax'
        if mode == UC_MODE_32:
            reg = 'eax'
        rax_value = mu.reg_read(self.RegisterMap[reg])

        if rax_value > 0:
            length = 8
            while True:
                data = mu.mem_read(rax_value, length)
                if data[-2:] == b"\x00\x00":
                    break
                length += 8
                if length > 512:
                    break

            if data[1] == 0:
                data = data.decode("utf-16").strip("\x00")
            else:
                data = data.decode("utf-8").strip("\x00")

        if data:
            result['data'] = data
            result['data_length'] = len(data)
        return result

    def deobfuscate_stack(self, start_address, end_address, retry=0, string_length=0, mode=UC_MODE_32):
        """
        Primarily tested with ADVObfuscated strings. Works with similar methods which write obfuscated bytes to the
        stack, deobfucstate them, and return the result.

        :param start_address:
        :param end_address:
        :param retry:
        :param string_length:
        :param code_size:
        :param mode:
        :return:
        """

        self.logger.debug("[*] Initializing")
        result = {}

        try:

            hooks = [
                (UC_HOOK_MEM_WRITE, self.hook_mem_access),
                (UC_HOOK_MEM_READ, self.hook_mem_access),
                (UC_HOOK_MEM_INVALID, self.hook_mem_invalid),
                (UC_HOOK_CODE, self.hook_code)
            ]
            try:
                mu = self.emulate(start_address, end_address, hooks)
            except EmulationTimeout:
                self.logger.debug("Emulation Timeout...setting patch_inc hook")
                hooks = [
                    (UC_HOOK_MEM_WRITE, self.hook_mem_access),
                    (UC_HOOK_MEM_READ, self.hook_mem_access),
                    (UC_HOOK_MEM_INVALID, self.hook_mem_invalid),
                    (UC_HOOK_CODE, self.hook_patch_inc)
                ]
                mu = self.emulate(start_address, end_address, hooks)

            if not mu:
                return result

            for reg in self.RegisterMap.keys():
                try:
                    result[reg] = mu.reg_read(self.RegisterMap[reg])
                except Exception as ex:
                    self.logger.error("Error reading register :: %s" % reg)
                    self.logger.error("Error: %s" % ex)

            stack_data = b""

            self.logger.debug("Raw: %s" % self.stack_data)
            self.logger.debug("Lazy Stack: %s" % self.decoded_stack)

            if self.decoded_stack:
                ds = self.decoded_stack.replace("\x00", "")
                result['data'] = ds
                result['data_length'] = len(ds)
                return result

            # Check if a string length is defined.
            if string_length == 0:
                pass
                # TODO: This would never be set..update this
                # if mrefs:
                #     result = self._get_func_decoded(mu, mode)
                #     if result:
                #         return result

            self.logger.debug("Attempting to auto extract data...")

            # Attempt to automatically extract the written string from the stack.
            #
            self.stack_offset = self.stack_base + 0x1000

            cursor = self.first_write_address
            self.logger.debug('Cursor: %x' % cursor)
            self.logger.debug('Stack Offset: %x' % self.stack_offset)
            self.logger.debug('Last Write Address:: %x' % self.last_write_address)

            # if cursor < self.last_write_address:
            #    test = mu.mem_read(cursor, self.last_write_address - cursor)
            #    print(test)

            self.logger.debug('String Length: %s' % string_length)

            if cursor == 0:
                self.logger.error("No write detected!")
                self.logger.error("Extraction failed!")
                return {}

            if string_length > 0:
                self.logger.debug("Reading [%d] bytes from memory" % string_length)
                test = mu.mem_read(cursor, string_length)
                self.logger.debug('Extracted Bytes: %s' % test)
                result['data'] = test.decode("utf-8").replace("\x00", "")
            else:
                counter = 0
                while cursor < self.stack_base + self.stack_size:
                    if counter > 512:
                        break
                    # counter += 1
                    data = mu.mem_read(cursor, 1)
                    if self.stack_grow:
                        cursor += 1
                    else:
                        cursor -= 1
                    if data == b"\x00":
                        if len(stack_data) > 2:
                            if not stack_data[1] == "\x00":
                                break
                    stack_data = stack_data + data

                self.logger.debug("Extracted:  %s" % stack_data)
                self.logger.debug(type(stack_data))

                if len(stack_data) > 1:
                    if stack_data[1] == 0:
                        try:
                            stack_data = stack_data.decode("utf-16")
                        except UnicodeDecodeError:
                            # probably have bad data
                            # just swallow this for now
                            # Which is probably a bad idea
                            pass
                    else:
                        stack_data = stack_data.decode("utf-8")

                    result['data'] = stack_data
                    result['data_length'] = len(stack_data)
                else:

                    result['data'] = ''
                    result['data_length'] = 0

                # if all(c in string.printable for c in self.decoded_stack.replace("\x00", "")):
                # if all(c in string.printable for c in tmp.replace(b"\x00", "")):
                #    result['data'] = tmp.decode("utf-8")
                #    result['data_length'] = len(tmp.decode("utf-8"))
                # else:
                #    self._debug_log("Error extacted unprintable bytes %s" % tmp)

            try:
                self.logger.debug('Extracted Data: %s' % result['data'])
                result['data_length'] = len(result['data'])
            except KeyError as ke:
                self.logger.error('Error processing data: %s' % ke)
                pass

            return result

        except Exception as e:
            if retry == 0:
                self.logger.error(" [!] Emulation error: %s" % e)
                self.logger.error(" [*] Retrying...")
                self.read_switch = False

                # Enable Tracing
                # self.trace = True
                self.stack_data = ""
                self.decoded_stack = ""
                return self.deobfuscate_stack(start_address, end_address, retry=1, mrefs=mrefs, mode=mode)
            else:
                self.logger.error(" [!] Fatal error emulating [%s]" % e)
