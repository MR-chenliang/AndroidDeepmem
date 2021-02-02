

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers.basic import Address
from volatility.renderers import TreeGrid

class linux_lsof(linux_pslist.linux_pslist):
    """Lists file descriptors and their path"""
    """lists opened fiels!!!"""

    def unified_output(self, data):
        return TreeGrid([("Offset",Address),
                         ("Name",str),
                        ("Pid", int),
                       ("FD", int),
                       ("Path", str)],
                        self.generator(data))

    def generator(self, data):
        for task in data:
            for filp, fd in task.lsof():
                yield (0, [Address(task.obj_offset),str(task.comm),int(task.pid), int(fd), str(linux_common.get_path(task, filp))])


    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset","#018x"),
                                  ("Name","30"),
                                  ("Pid", "8"),
                                  ("FD", "8"),
                                  ("Path", "")])

        for task in data:
            for filp, fd in task.lsof(): 
                self.table_row(outfd, Address(task.obj_offset), str(task.comm), task.pid, fd, linux_common.get_path(task, filp))