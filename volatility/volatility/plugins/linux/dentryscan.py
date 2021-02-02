
import sys, os
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.mount as linux_mount
import volatility.plugins.linux.flags as linux_flags
import volatility.debug as debug
import volatility.utils as utils
from volatility.plugins.linux.find_file import linux_find_file

OUTPUT_PATH = '../create_graph/objects/'

class linux_inodescan(linux_common.AbstractLinuxCommand):
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self.seen_dents = set()

    def _walk_sb(self, dentry_param, parent):
        ret = []

        if hasattr(dentry_param, "d_child"):
            walk_member = "d_child"
        else:
            walk_member = "d_u"

        for dentry in dentry_param.d_subdirs.list_of_type("dentry", walk_member):
            dentry_addr = dentry.v()

            # corruption
            if dentry_addr == dentry_param.v():
                continue

            if dentry_addr in self.seen_dents:
                break

            self.seen_dents.add(dentry_addr)

            if not dentry.d_name.name.is_valid():
                continue

            inode = dentry.d_inode

            ivalid = False
            if inode and inode.is_valid():
                if inode.i_ino == 0 or inode.i_ino > 100000000000:
                    continue
                ivalid = True

            # do not use os.path.join
            # this allows us to have consistent paths from the user
            name = dentry.d_name.name.dereference_as("String", length=255)
            new_file = parent + "/" + name
            ret.append((new_file, dentry))

            if ivalid and inode.is_dir():
                ret = ret + self._walk_sb(dentry, new_file)

        return ret

    def _get_sbs(self):
        ret = []

        for (sb, _dev_name, path, fstype, _rr, _mnt_string) in linux_mount.linux_mount(self._config).calculate():
            ret.append((sb, path))

        return ret

    def walk_sbs(self, sbs = []):
        if sbs == []:
            linux_common.set_plugin_members(self)
            sbs = self._get_sbs()

        for (sb, sb_path) in sbs:
            if sb_path != "/":
                parent = sb_path
            else:
                parent = ""

            rname  = sb.s_root.d_name.name.dereference_as("String", length = 255)
            if rname and len(rname) > 0:
                yield (sb, sb_path, sb_path, sb.s_root)

            for (file_path, file_dentry) in self._walk_sb(sb.s_root, parent):
                yield (sb, sb_path, file_path, file_dentry)

    def inode_scan(self):
        for (_, _, file_path, file_dentry) in self.walk_sbs():
            yield (file_path, file_dentry, file_dentry.d_inode)

    def calculate(self):
        dic_addr_to_type = {}
        dic_type_to_size = {}
        for (_, dentry, inode) in self.inode_scan():    # inode.obj_type = None???
            #print (inode.size())  # inode.size() = 8
            if(dentry.size() > 8):
                dic_addr_to_type[dentry.obj_offset] = dentry.obj_type
                dic_type_to_size[dentry.obj_type] = dentry.size()

        list_addr = dic_addr_to_type.keys()

        list_addr.sort()
        file_name = OUTPUT_PATH + 'dentry.txt'
        with open(file_name, 'w') as f:
            for addr in list_addr:
                f.write(hex(addr).replace('L', '') + '\t' + dic_addr_to_type[addr]
                        + '\t' + str(dic_type_to_size[dic_addr_to_type[addr]]) + '\n')





    def render_text(self, outfd, data):#data = self.calculate()
        # shown_header = 0
        #
        # for (file_path, inode) in data:
        #     if not shown_header:
        #         self.table_header(outfd, [("Inode Number", "16"), ("Inode", "[addr]"), ("File Path", "")])
        #         shown_header = 1
        #
        #     inode_num = inode.i_ino
        #
        #     self.table_row(outfd, inode_num, inode, file_path)
        return