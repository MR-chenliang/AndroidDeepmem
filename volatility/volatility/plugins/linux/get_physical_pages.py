import os
import sys
import volatility.utils as utils
import volatility.plugins.linux.common as linux_common

PAGES_OUTPUT_PATH = '../create_graph/pages/'

class linux_get_physical_pages(linux_common.AbstractLinuxCommand):
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self.kernel_address_space = None

    def calculate(self):
        image_name = os.path.basename(self._config.LOCATION)
        self.kernel_address_space = utils.load_as(self._config)
        # kernel_address_space = class:plugins.addrspaces.amd64.LinuxAMD64PagedMemory
        available_pages = self.kernel_address_space.get_available_pages()


        dict_page_addr_to_size = {}
        for addr, size in available_pages:
            #print(addr, size)
            if addr > 0x880000000000:
                addr += 0xffff000000000000
                dict_page_addr_to_size[addr] = size
        list_paddr = []
        with open(PAGES_OUTPUT_PATH + image_name + '.pages', 'w') as output:
            list_addr = dict_page_addr_to_size.keys()
            list_addr.sort()
            for addr in list_addr:
                size = dict_page_addr_to_size[addr]
                physical_addr = self.kernel_address_space.vtop(addr)

                list_paddr.append(addr)

                output.write(str(addr) + '\t' + str(physical_addr) + '\t' + str(size) + '\n')
        list_paddr.sort()
        print (list_paddr[-1])#max(paddr)

    def render_text(self, outfd, data):
        if data!=None:
            outfd.write(data)