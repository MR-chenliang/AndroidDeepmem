import volatility.plugins.linux.common as linux_common
import volatility.obj as obj
import volatility.plugins.linux.lsmod as lsmod


OUTPUT_PATH = '../create_graph/objects/'
OBJ_SET = {'task_struct', 'thread', 'module', 'file', 'file_operations', 'dentry', 'inode'}

# PROFILE = 'Linuxgoldfish-4_14x64'

class linux_miniscan(linux_common.AbstractLinuxCommand):
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)

    def allprocs(self):
        linux_common.set_plugin_members(self)
        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)

        for task in init_task.tasks:
            yield task

    def generate_thread(self):
        all_tasks = list(self.allprocs())
        for task in all_tasks:
            for thread in task.threads():
                yield thread

    def modscan(self):
        modules = []
        for (module, _, _) in lsmod.linux_lsmod(self._config).calculate():
            modules.append(module)
        return modules

    def calculate(self):
        dict_addr_to_type = {}
        dict_type_to_size = {}
        all_tasks = list(self.allprocs()) # gather task_structs

        all_threads = list(self.generate_thread())
        for objc in all_threads:
            dict_addr_to_type[objc.obj_offset] = 'thread'
            dict_type_to_size['thread'] = objc.size()

        all_modules = self.modscan()
        structs = all_tasks
        structs.extend(all_modules)

        for objc in structs:
            dict_addr_to_type[objc.obj_offset] = objc.obj_type
            dict_type_to_size[objc.obj_type] = objc.size()

        addrs = dict_addr_to_type.keys()
        addrs.sort()
        file_name = OUTPUT_PATH + 'task-threads-modules0.txt'
        with open(file_name, 'w') as f:
            for addr in addrs:#type(addr)=long
                f.write(hex(addr).replace('L','') + '\t' + dict_addr_to_type[addr] + '\t' + str(dict_type_to_size[dict_addr_to_type[addr]]) + '\n')


    def render_text(self, outfd, data):#important!!!!
        return