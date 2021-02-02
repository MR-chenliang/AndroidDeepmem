import volatility.plugins.linux.common as linux_common
import volatility.obj as obj


OUTPUT_PATH = '../create_graph/objects/'
# PROFILE = 'Linuxgoldfish-4_14x64'

class linux_taskscan(linux_common.AbstractLinuxCommand):

    def allprocs(self):
        linux_common.set_plugin_members(self)

        init_task_addr = self.addr_space.profile.get_symbol("init_task")
        init_task = obj.Object("task_struct", vm = self.addr_space, offset = init_task_addr)

        for task in init_task.tasks:
            yield task

    def task_scan(self):
        tasks = list(self.allprocs())
        # print (dir(tasks[0]))
        print (dir(tasks[0].get_process_address_space()))
        # dict_task_addr_to_size = dict((p.obj_offset, p.size()) for p in all_tasks)
        # list_task_addr = dict_task_addr_to_size.keys()
        # return list_task_addr,dict_task_addr_to_size[list_task_addr[0]]

    def calculate(self):
        dict_addr_to_type = {}
        dict_type_to_size = {}

        self.task_scan()
        # for addr in list_task_addr:
        #     dict_addr_to_type[addr] = 'task_struct'
        # dict_type_to_size['task_struct'] = task_size

        # addrs = dict_addr_to_type.keys()
        # addrs.sort()
        # file_name = OUTPUT_PATH + 'tasks.txt'
        # with open(file_name, 'w') as f:
        #     for addr in addrs:#type(addr)=long
        #         f.write(hex(addr).replace('L','') + '\t' + dict_addr_to_type[addr]
        #                 + '\t' + str(dict_type_to_size[dict_addr_to_type[addr]]) + '\n')


    def render_text(self, outfd, data):#important!!!!
        return