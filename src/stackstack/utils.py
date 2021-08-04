import idaapi
import idc
import idautils
import http.client


class IdaHelpers(object):

    SegmentAlignMap = {
        idaapi.saAbs: 0,
        idaapi.saRelByte: 1,
        idaapi.saRelWord: 2,
        idaapi.saRelPara: 16,
        idaapi.saRelPage: 256,
        idaapi.saRelDble: 4,
        idaapi.saRel32Bytes: 32,
        idaapi.saRel64Bytes: 64,
        idaapi.saRelQword: 8,
        idaapi.saRel512Bytes: 512,
        idaapi.saRel1024Bytes: 1024,
        idaapi.saRel2048Bytes: 2048,
    }

    @staticmethod
    def add_comment(offset, comment, hexrays=True, overwrite=True):
        """
        Add a comment to the disassembly at the specified offset and optionally in the Hexray's decompilation.

        :param offset:   Offset to add the comment at
        :param comment:  The comment
        :param hexrays:  Apply to hexrays decompile window
        :param overwrite: Overwrite existing comment
        """

        if not overwrite:
            existing_comment = idc.GetCommentEx(offset, 0)
            if existing_comment:
                comment = "%s; %s" % (existing_comment, comment)
                
        # Add comment to disassembly
        idc.set_cmt(offset, 'Decoded: %s' % comment, 0)

        if hexrays:
            cfunc = idaapi.decompile(offset)
            fmap = cfunc.get_eamap()
            tl = idaapi.treeloc_t()
            tl.ea = fmap[offset][0].ea
            tl.itp = idaapi.ITP_SEMI
            cfunc.set_user_cmt(tl, comment)
            cfunc.save_user_cmts()
            cfunc.refresh_func_ctext()

    @staticmethod
    def add_bookmark(offset, comment, check_duplicate=True):
        """
        Add a bookmark and optionally skip if one exists for the offset.

        :param offset:
        :param comment:
        :param check_duplicate:
        :return:
        """
        for bslot in range(0, 1024, 1):
            slotval = idc.get_bookmark(bslot)
            if check_duplicate:
                if slotval == offset:
                    break

            if slotval == 0xffffffffffffffff:
                idc.put_bookmark(offset, 0, 0, 0, bslot, "SSB: %s" % comment)
                break

    @staticmethod
    def get_bitness():
        if idaapi.get_inf_structure().is_64bit():
            return 2
        return 1

    @staticmethod
    def get_arch():
        if IdaHelpers.get_bitness() > 1:
            return 64
        return 32

    @staticmethod
    def add_section(offset, name, bitness, size=0x1000, base=0, cls='DATA'):
        """
        Add a segment at the specified offset

        :param offset:
        :param name:
        :param bitness:
        :param size:
        :param base:
        :param cls:
        :return:
        """
        if offset == 0:
            offset = idaapi.inf_get_max_ea()
            if offset == idaapi.BADADDR:
                offset = 0
                for s in idautils.Segments():
                    if offset < idc.get_segm_end(s):
                        offset = idc.get_segm_end(s)

        sdef = idaapi.segment_t()

        flags = idaapi.ADDSEG_OR_DIE

        sdef.start_ea = offset
        sdef.end_ea = offset + size
        sdef.sel = idaapi.setup_selector(base)
        sdef.align = idaapi.saRelPara
        sdef.perm = idaapi.SEGPERM_READ
        sdef.bitness = bitness
        sdef.comb = idaapi.scPub

        idaapi.add_segm_ex(sdef, name, cls, flags)


class Update(object):

    @staticmethod
    def check_version(version):
        try:
            req = http.client.HTTPSConnection("raw.githubusercontent.com")
            req.request("GET", "/idiom/stackstack/main/version")
            res = req.getresponse()
            if res.status == 200:
                remote_ver = res.read()
                if float(remote_ver.decode()) > version:
                    return float(remote_ver.decode())
            return 0
        except Exception as ex:
            print("Error checking version: %s" % ex)
            return 0
