import os
import volatility.plugins.linux.common as linux_common
import volatility.obj as obj
import volatility.plugins.linux.lsmod as lsmod
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.filescan as filescan


OUTPUT_PATH = '../create_graph/objects/'
OBJ_SET = {'task_struct', 'thread', 'module', 'file', 'file_operations', 'dentry', 'inode'}

# PROFILE = 'Linuxgoldfish-4_14x64'

class linux_objectscan(linux_common.AbstractLinuxCommand):
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)

    def generate_thread(self):
        tasks = linux_pslist.linux_pslist(self._config).calculate()
        for task in tasks:
            for thread in task.threads():
                yield thread

    def modscan(self):
        modules = []
        for (module, _, _) in lsmod.linux_lsmod(self._config).calculate():
            modules.append(module)
        return modules

    def calculate(self):
        image_name = os.path.basename(self._config.LOCATION)
        dict_addr_to_type, dict_type_to_size = filescan.linux_filescan(self._config).calculate()
        tasks = list(linux_pslist.linux_pslist(self._config).calculate())  # gather task_structs

        threads = list(self.generate_thread())
        for objc in threads:
            dict_addr_to_type[objc.obj_offset] = 'thread'
            dict_type_to_size['thread'] = objc.size()

        all_modules = self.modscan()
        structs = tasks
        structs.extend(all_modules)

        for objct in structs:
            dict_addr_to_type[objct.obj_offset] = objct.obj_type
            dict_type_to_size[objct.obj_type] = objct.size()

        addrs = dict_addr_to_type.keys()
        addrs.sort()
        file_name = OUTPUT_PATH + image_name + '.objects'
        with open(file_name, 'w') as f:
            for addr in addrs:
                f.write(hex(addr).replace('L', '') + '\t' + dict_addr_to_type[addr] + '\t' + str(dict_type_to_size[dict_addr_to_type[addr]]) + '\n')


    def render_text(self, outfd, data):#important!!!!
        return