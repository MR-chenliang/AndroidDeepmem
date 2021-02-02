
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.lsmod as linux_lsmod

OUTPUT_PATH = '../create_graph/objects/'


class linux_filescan(linux_common.AbstractLinuxCommand):    # from plugin:check_fops
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)

    def get_open_files(self):
        tasks = linux_pslist.linux_pslist(self._config).calculate()
        for task in tasks:
            for filp, i in task.lsof(): #open file!!!!
                yield filp

    def filescan(self):
        linux_common.set_plugin_members(self)
        filps = list(self.get_open_files())
        return filps

    def calculate(self):
        files = self.filescan()

        dic_addr_to_type = {}
        dic_type_to_size = {}
        f_structs = []

        for file in files:
            f_ops = obj.Object("file_operations", offset = file.f_op.obj_offset, vm = self.addr_space)
            # return object of offset!!  see line 42 in check_fops.py!
            dentry = obj.Object("dentry", offset = file.dentry.obj_offset, vm = self.addr_space)
            inode = obj.Object("inode", offset=dentry.d_inode.obj_offset, vm=self.addr_space)
            f_structs.extend([file, f_ops, dentry, inode])

        for struct in f_structs:
            dic_addr_to_type[struct.obj_offset] = struct.obj_type
            dic_type_to_size[struct.obj_type] = struct.struct_size

        return dic_addr_to_type, dic_type_to_size;
        # list_addr = dic_addr_to_type.keys()
        #
        # list_addr.sort()
        # file_name = OUTPUT_PATH + 'file-fops-dentry-inode.txt'
        # with open(file_name, 'w') as f:
        #     for addr in list_addr:
        #         f.write(hex(addr).replace('L', '') + '\t' + dic_addr_to_type[addr]
        #                 + '\t' + str(dic_type_to_size[dic_addr_to_type[addr]]) + '\n')

    def render_text(self, outfd, data):
        return

