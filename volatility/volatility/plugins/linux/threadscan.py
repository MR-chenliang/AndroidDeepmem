import volatility.plugins.linux.pslist as linux_pslist

class linux_threadscan(linux_pslist.linux_pslist):

    def render_text(self, outfd, data):
        for task in data:
            for thread in task.threads():
                print(hex(thread.obj_offset).replace('L','') + '\t' + str(thread.size()))