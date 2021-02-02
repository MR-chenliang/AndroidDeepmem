
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers.basic import Address
from volatility.renderers import TreeGrid

class linux_threads(linux_pslist.linux_pslist):
    """ Prints threads of processes """

    def unified_output(self, data):
        return TreeGrid([("Offset",Address),
                        ("NameProc",str),
                         ("TGID",int),
                         ("ThreadPid",str),
                            ("ThreadName", str),
                        ("thread_offset",Address),
                            ("Addr_limit",Address),
                            ("uid_cred",int),
                            ("gid_cred",int),
                            ("euid_cred",int)
                        ],
                        self.generator(data))

    def generator(self, data):

        for task in data:
            euidcred = task.euid
            uidcred = task.uid
            gidcred = task.gid
            for thread in task.threads():
                addr_limit = self.get_addr_limit(thread)
                yield(0,[Address(task.obj_offset),
                         str(task.comm),
                         int(task.tgid),
                         str(thread.pid),
                         str(thread.comm),
                         Address(thread.obj_offset),
                         Address(addr_limit),
                         int(uidcred),
                         int(gidcred),
                         int(euidcred)
                ])

    def get_addr_limit(self, thread, addrvar_offset = 8 ):
        """
        Here we read the addr_limit variable of a thread
        by reading at the offset of the thread plus
        the offset of the addr_limit variable inside the thread_info
        :param thread: thread from which we want the information
        :param addrvar_offset: offset of the addr_limit var in the thread_info
        :return: the addr_limit
        """
        addr_space = thread.get_process_address_space()
        offset = thread.obj_offset + addrvar_offset
        if addr_space.__class__ == "LinuxAMD64PagedMemory":
            return addr_space.read_long_long_phys(offset)
        else:
            return addr_space.read_long_phys(offset)

    def render_text(self, outfd, data):
        for task in data:
            #outfd.write("\nProcess Name: {}\nProcess ID: {}\n".format(task.comm, task.tgid))
            self.table_header(outfd, [('Thread PID', '13'), ('Thread Name', '16')])
            for thread in task.threads():   # task.threads() = list
                print (thread.size())  # thread.obj_type = task_struct!
                #self.table_row(outfd, str(thread.pid), thread.comm)

    


