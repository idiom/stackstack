from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
# import sip


from unicorn import *
from unicorn.x86_const import *
from enum import Enum

import idaapi
import idautils
import idc
import ida_ua
import logging
from stackstack.sue import BaseEmulator

class SIT(BaseEmulator):
    """
    Simple Instruction Tracer

    """
    def __init__(self, code_base=0x18000000,
                 stack_base=0xA0000000,
                 stack_size=0x10000,
                 mode=UC_MODE_64,
                 loglevel=logging.DEBUG):

        self.logger = logging.getLogger()
        self.logger.setLevel(loglevel)
        self._prev_address = 0

        self.twin = SITWindow()

        super().__init__(code_base, stack_base, stack_size, mode, self.logger)

    def _get_reg_values(self, mu, address):
        rdata = ""
        ops = []
        for x in range(2):
            if idc.get_operand_type(address, x) == idaapi.o_reg:
                try:
                    cur_op = idc.print_operand(address, x)
                    if cur_op in ops:
                        continue
                    ops.append(cur_op)
                    reg_data = mu.reg_read(self.RegisterMap[cur_op])
                    rdata += "%s: 0x%x\n" % (cur_op, reg_data)
                except KeyError:
                    pass
        return rdata


    def trace_code(self, mu, address, size, user_data):
        """
        Hook to emit trace information to ida
        :param mu:
        :param address:
        :param size:
        :param user_data:
        :return:
        """
        rdata = self._get_reg_values(mu, address)
        pdata = ""
        comment = rdata
        if self._prev_address:
            pdata = self._get_reg_values(mu, self._prev_address)

        self.logger.debug("rdata: %s" % rdata)
        self.logger.debug("pdata: %s" % pdata)

        self.twin.update_entry_data(address,
                                    idc.generate_disasm_line(address, 0),
                                    rdata,
                                    pdata,
                                    "entry mem test")

        self._prev_address = address
        if comment:
            idc.set_cmt(address, comment, 0)
        self.logger.debug(comment)

    def emulate_trace(self, start_address, end_address):
        hooks = [
            (UC_HOOK_CODE, self.trace_code)
        ]
        self.logger.debug("Starting Trace")
        # plg = MyPluginFormClass()
        # plg.Show("Demo Search")
        self.twin.Show("StackStack Tracer")

        mu = self.emulate(start_address, end_address, hooks)
        self.logger.debug("Trace Complete")

        for reg in self.RegisterMap.keys():
            try:
                self.logger.info("%s: %x" % (reg, mu.reg_read(self.RegisterMap[reg])))
            except Exception as ex:
                self.logger.error("Error reading register :: %s" % reg)
                self.logger.error("Error: %s" % ex)

    def trace(self, start, end):
        pass

class TracerColumnOffsets(Enum):
    Address = 0
    Instruction = 1
    PreExec = 2
    PostExec = 3
    Data = 4


class SITWindow(PluginForm):

    # options = PluginForm.WOPN_DP_BOTTOM | PluginForm.WOPN_TAB
    options = PluginForm.WOPN_DP_RIGHT

    # def __init__(self):
    #    # self.options = PluginForm.FORM_TAB | PluginForm.FORM_ONTOP
    #    self.options = PluginForm.WOPN_DP_BOTTOM | PluginForm.WOPN_ONTOP | PluginForm.WOPN_TAB



    def OnCreate(self, form):
        """
        Called when the widget is created
        """

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.row_cursor = 0
        self.PopulateForm()



    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        # create an empty list
        # self.list = QtWidgets.QListWidget()
        # self.list.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        # self.list.currentItemChanged.connect(self.print_item)

        # item
        # self.list.addItem("WE NEED A HERO")

        # table
        self.table = QtWidgets.QTableWidget()
        self.table.setRowCount(0)
        self.table.setColumnCount(5)
        """
        0x1 xor eax, eax    eax=0x1 eax=0x0 
        """
        self.table.setHorizontalHeaderLabels(["Address",
                                              "Instruction",
                                              "PreEXEC",
                                              "PostEXEC",
                                              "Data"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)


        self.table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        layout.addWidget(self.table)

        # make our created layout the dialogs layout
        self.parent.setLayout(layout)

    def update_entry_data(self, address, instruction, reg_data, post_data, data=None):
        self.table.setRowCount(self.table.rowCount() + 1)

        self.table.setItem(self.row_cursor,
                           TracerColumnOffsets.Address.value,
                           QtWidgets.QTableWidgetItem("0x%x" % address))

        self.table.setItem(self.row_cursor,
                           TracerColumnOffsets.Instruction.value,
                           QtWidgets.QTableWidgetItem(instruction))

        self.table.setItem(self.row_cursor,
                           TracerColumnOffsets.PreExec.value,
                           QtWidgets.QTableWidgetItem(reg_data))

        self.table.setItem(self.row_cursor - 1,
                           TracerColumnOffsets.PostExec.value,
                           QtWidgets.QTableWidgetItem(post_data))

        self.table.setItem(self.row_cursor,
                           TracerColumnOffsets.Data.value,
                           QtWidgets.QTableWidgetItem(data))6

        self.table.resizeRowToContents(self.row_cursor)
        self.row_cursor += 1

    def add_item(self):
        self.list.addItem("BRRRRRRRR")

    def print_item(self):
        print(self.list.currentItem().text())


    def OnClose(self, form):
        """
        Called when the widget is closed
        """
        pass