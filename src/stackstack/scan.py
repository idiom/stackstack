import yara
import idautils
import idc
import logging
import os.path

class ScanEngineBase(object):
    pass

class YaraScanner(ScanEngineBase):
    """

    """
    VERSION = "1.0.0"

    def __init__(self, rule_file=None, rules=[], loglevel=logging.DEBUG):
        self.logger = logging.getLogger()
        self.logger.setLevel(loglevel)

        if rule_file:
            # load external rule file.
            pass

        self.raw_rules = [
            """rule scan_a{strings: $ = {c6 45 ?? 00 c6 45 ?? ?? c6 45} condition: all of them}""",
            """rule scan_b{strings: $ = {c6 85 [2-3] ff ff 00 [0-2] c6 85 [2-3] ff ff} condition: all of them}""",
            """rule scan_c{strings: $ = {(c6|c7) 4? [2-5] (c6|c7) 4? } condition: all of them}""",
            """rule scan_d{strings: $ = {(c6|c7) 4? ?? 00 (c6|c7) 4? ?? ?? (c6|c7) 4? } condition: all of them}"""
        ]

        # """rule scan_d{strings: $ = {c6 40 ?? 00 c6 40 ?? ?? c6 40 } condition: all of them}""",
        # """rule scan_c{strings: $ = {c6 4? ?? ?? c6 4? ?? ?? c6 4? ?? ?? c6 4? ?? ?? } condition: all of them}"""

        self.raw_rules.extend(rules)
        self.rules = self._compile_rules(self.raw_rules)

    def _compile_ext_rules(self, rulefile):
        if os.path.isfile(rulefile):
            try:
                ext_rules = yara.compile(rulefile)
                self.rules.extend(ext_rules)
            except Exception as ex:
                self.logger.error("Error loading rulefile: %s" % ex)

    def _compile_rules(self, rules):
        compiled = []
        for rule in rules:
            try:
                compiled.append(yara.compile(source=rule))
            except Exception as ex:
                self.logger.debug(" [!] Error compiling rule: %s" % ex)
        return compiled

    def scan_functions(self, ignore_libs=True, match_overlay_range=64):
        """

        Scan all functions optionally excluding lib functions

        :param ignore_libs: Ignore library functions
        :param match_overlay_range: Exclude results within this range of the last match
        :return:
        """
        results = {}
        for func_entry in idautils.Functions():
            if ignore_libs:
                if idc.get_func_attr(func_entry, idc.FUNCATTR_FLAGS) & idc.FUNC_LIB:
                    self.logger.debug("Skipping lib function %s" % idc.get_func_name(func_entry))
                    continue

            func_name = idc.get_func_name(func_entry)

            func_data = idc.get_bytes(func_entry, idc.get_func_attr(func_entry, idc.FUNCATTR_END) - func_entry)
            for rule in self.rules:
                last_match_offset = 0
                matches = rule.match(data=func_data)

                if not matches:
                    continue

                for rule_match in matches:
                    for match in rule_match.strings:

                        if last_match_offset > match[0] > last_match_offset - match_overlay_range:
                            continue
                        elif last_match_offset < match[0] < last_match_offset + match_overlay_range:
                            continue

                        self.logger.debug("Match at [%x]" % (func_entry + match[0]))
                        last_match_offset = match[0]
                        try:
                            results[func_name] += 1
                        except KeyError:
                            results[func_name] = 1
        return results

    def scan_function(self, data):
        """
        Scan the current function for obfuscated blobs

        :param data:
        :return:
        """
        values = []
        for rule in self.rules:
            matches = rule.match(data=data)

            if not matches:
                continue

            for rule_match in matches:
                for match in rule_match.strings:
                    self.logger.debug("Match at %x" % match[0])
                    values.append(match[0])
        return values