import os
import sys
from time import gmtime,strftime

PROFILE = 'Linuxgoldfish-4_14x64'
#PROFILE = 'LinuxLinux64x64'

def log(message):#display time&message
    print('%s\t%s' %(strftime("%Y-%m-%d %H:%M:%S",gmtime()),message))
    sys.stdout.flush()

def main():
     image_path = '../mem_dumps/'
     image_files = os.listdir(image_path)
     image_files.sort()
     os.system('mkdir -p objects pages')
     object_files = os.listdir('./objects')
     page_files = os.listdir('./pages')

     for dump_name in image_files:
        log(dump_name)
        cmd_object_scan = 'cd ../volatility;python vol.py -f ' + image_path + dump_name + ' --profile=' + PROFILE + ' linux_objectscan;cd -'
        if dump_name + '.objects' not in object_files:
            log(cmd_object_scan)
            os.system(cmd_object_scan)

        cmd_get_pages = 'cd ../volatility;python vol.py -f ' + image_path + dump_name + ' --profile=' + PROFILE + ' linux_get_physical_pages;cd -'
        if dump_name + '.pages' not in page_files:
            log(cmd_get_pages)
            os.system(cmd_get_pages)

        cmd_build_graph = 'python graph.py ' + image_path + dump_name
        log(cmd_build_graph)
        os.system(cmd_build_graph)



if __name__ == "__main__":
    main()