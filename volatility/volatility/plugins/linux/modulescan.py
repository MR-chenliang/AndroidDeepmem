import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsmod as lsmod

OUTPUT_PATH = '../objects/'

class linux_modulescan(linux_common.AbstractLinuxCommand):

    def modscan(self):
        modules = []
        for (module, _, _) in lsmod.linux_lsmod(self._config).calculate():
            modules.append(module)
        return modules

    def calculate(self):
        dict_addr_to_type = {}
        dict_type_to_size = {}
        # all_modules = lsmod.linux_lsmod(self._config).get_modules()##cankao check_fops.calculate
        all_modules = self.modscan()
        for m in all_modules:
            dict_addr_to_type[m.obj_offset] = m.obj_type
            dict_type_to_size[m.obj_type] = m.size()

        list_addr = dict_addr_to_type.keys()


        list_addr.sort()
        file_name = OUTPUT_PATH + 'modules.txt'
        with open(file_name, 'w') as f:
            for addr in list_addr:
                f.write(hex(addr).replace('L', '') + '\t' + dict_addr_to_type[addr]
                        + '\t' + str(dict_type_to_size[dict_addr_to_type[addr]]) + '\n')


    def render_text(self, outfd, data):
        return
