import os
import sys
from time import gmtime, strftime

HOP = 3
OUTPUT_PATH = './graph/'
OBJECT_PATH = './objects/'
PAGE_PATH = './pages/'

MAX_NODE_SIZE = 64

SEARCH_LEN = 128

MAX_NODE_COUNT = 220000

WORD_SIZE = 8

g_dict_paddr_to_vaddr = {}
g_dict_vaddr_to_paddr = {}

OBJ_TYPES = ['task_struct', 'thread', 'module', 'file', 'file_operations', 'dentry', 'inode']
BUILD_TYPE = 'train'

def main():
    #print_configure()
    image_path = sys.argv[1]
    if len(sys.argv) >= 3 and sys.argv[2] == 'test':
        global BUILD_TYPE
        BUILD_TYPE = 'test'
    image_name = os.path.basename(image_path)
    log(image_name)

    log('get available_pages')
    dict_paddr_to_size, set_vaddr_page = read_available_pages(image_name)
    #print(len(dict_paddr_to_size)) #44372

    log('find pointer-dest map')
    dict_vaddr_to_dest = get_pointer_to_dest(image_path, dict_paddr_to_size, set_vaddr_page)
    print(len(dict_vaddr_to_dest)) #2687

    log('get node vaddr list')
    dict_node_vaddr_to_size = segmentation(dict_vaddr_to_dest.keys())
    list_node_vaddr = dict_node_vaddr_to_size.keys()
    list_node_vaddr.sort()

    set_node_vaddr = set(list_node_vaddr)

    log('find neighbors for each node')
    dict_node_to_ln, dict_node_to_rn, dict_node_to_lp, dict_node_to_rp = get_node_neighbor_seg(list_node_vaddr, dict_node_vaddr_to_size, dict_vaddr_to_dest, set_node_vaddr)


    log('generate vectors of nodes')
    dict_vaddr_to_vector = get_node_vector_seg(image_path, list_node_vaddr, dict_node_vaddr_to_size)

    log('get labeled node')
    dict_vaddr_to_label, set_type = get_vaddr_to_label(image_name, set_node_vaddr)
    log('len(dict_vaddr_to_label):\t%d' %len(dict_vaddr_to_label))

    if BUILD_TYPE == 'train':
        for obj_type in set_type:
            log('get kernel object node set')
            set_kernel_object_node = set()
            for node_vaddr in set_node_vaddr:
                if node_vaddr in dict_vaddr_to_label and obj_type in dict_vaddr_to_label[node_vaddr]:
                    set_kernel_object_node.add(node_vaddr)
            log('get training nodes')
            set_node_vaddr_train = get_train_subset_seg(set_kernel_object_node, dict_node_to_ln, dict_node_to_rn, dict_node_to_lp, dict_node_to_rp)

            log('write training files')
            if os.path.exists(OUTPUT_PATH) == False:
                print ('mkdir ' + OUTPUT_PATH)
                # print(os.system('pwd'))    # return -1??
                os.system('mkdir ' + OUTPUT_PATH)   # OUTPUT_PATH = './graph/'
            file_path = OUTPUT_PATH + 'graph.' + image_name.replace('lime', '') + obj_type
            list_node_vaddr_train = list(set_node_vaddr_train)
            list_node_vaddr_train.sort()
            write_output_file(file_path, list_node_vaddr_train, dict_node_to_ln, dict_node_to_rn, dict_node_to_lp, dict_node_to_rp, dict_node_vaddr_to_size, dict_vaddr_to_vector, dict_vaddr_to_label, obj_type)
    log('write tesing file')
    file_path = OUTPUT_PATH + 'graph.' + image_name.replace('lime', '') + 'all'
    write_output_file(file_path, list_node_vaddr, dict_node_to_ln, dict_node_to_rn, dict_node_to_lp, dict_node_to_rp, dict_node_vaddr_to_size, dict_vaddr_to_vector, dict_vaddr_to_label)
    log('finish')

def write_output_file(file_path, list_node_vaddr, dict_node_to_ln, dict_node_to_rn, dict_node_to_lp, dict_node_to_rp, dict_node_vaddr_to_size, dict_vaddr_to_vector, dict_vaddr_to_label, obj_type=None):#, set_node_vaddr_train):
    output_graph = open(file_path, 'w')
    for node_vaddr in list_node_vaddr:
        ln_str = rn_str = ''
        if node_vaddr in dict_node_to_ln:
            ln_str = str(hex(dict_node_to_ln[node_vaddr]))
        if node_vaddr in dict_node_to_rn:
            rn_str = str(hex(dict_node_to_rn[node_vaddr]))
        lp_str = set_to_string(dict_node_to_lp[node_vaddr])
        rp_str = set_to_string(dict_node_to_rp[node_vaddr])
        if node_vaddr in dict_node_vaddr_to_size and node_vaddr in dict_vaddr_to_vector:
            output_str = str(hex(node_vaddr)).replace('L', '') + '\t' + ln_str.replace('L', '') + '\t' + rn_str.replace('L', '') + '\t' + lp_str.replace('L', '') + '\t' + rp_str.replace('L', '') + '\t' + str(dict_node_vaddr_to_size[node_vaddr]) + '\t' + list_to_str(dict_vaddr_to_vector[node_vaddr])
            if node_vaddr in dict_vaddr_to_label and (obj_type == None or obj_type in dict_vaddr_to_label[node_vaddr]):
                output_str += '\t' + dict_vaddr_to_label[node_vaddr]
            output_str += '\n'
            output_graph.write(output_str)
    output_graph.close()

def print_configure():
    log('OUTPUT_PATH:\t%s' %OUTPUT_PATH)
    log('OBJECT_PATH:\t%s' %OBJECT_PATH)
    log('PAGE_PATH:\t%s' %PAGE_PATH)
    log('MAX_NODE_SIZE:\t%d' %MAX_NODE_SIZE)
    log('WORD_SIZE:\t%d' %WORD_SIZE)
    log('MAX_NODE_COUNT:\t%d' %MAX_NODE_COUNT)
    log('BUILD_TYPE:\t%s' %BUILD_TYPE)
    log('SEARCH_LEN:\t%d' %SEARCH_LEN)
    log('HOP:\t%d' %HOP)
    sys.stdout.flush()

def segmentation(list_ptr):
    set_ptr = set(list_ptr)
    dict_node_vaddr_to_size = {}
    list_ptr.sort()
    for idx, ptr in enumerate(list_ptr):
        if ptr + WORD_SIZE not in set_ptr:  # node_size != 0
            if idx + 1 < len(list_ptr):
                node_size = list_ptr[idx + 1] - (ptr + WORD_SIZE)   # +WORD_SIZE represente the size of ptr
                if node_size >= 4096:
                    pass
                elif node_size > MAX_NODE_SIZE:
                    dict_node_vaddr_to_size[ptr + WORD_SIZE] = MAX_NODE_SIZE
                else:
                    dict_node_vaddr_to_size[ptr + WORD_SIZE] = node_size
    return dict_node_vaddr_to_size

def get_node_neighbor_seg(list_node_vaddr, dict_node_vaddr_to_size, dict_ptr_to_dest, set_node_addr):
    set_ptr = set(dict_ptr_to_dest.keys())
    dict_node_to_ln = {}
    dict_node_to_rn = {}
    dict_node_to_lp = {}
    dict_node_to_rp = {}
    for idx, node_vaddr in enumerate(list_node_vaddr):
        if dict_node_vaddr_to_size[node_vaddr] <= 0:
            continue
        if idx - 1 >= 0:   # start: idx = 1
            #if two nodes are too far away, not neighbor
            if list_node_vaddr[idx] - list_node_vaddr[idx - 1] < 512:
                dict_node_to_ln[node_vaddr] = list_node_vaddr[idx - 1]
        if idx + 1 < len(list_node_vaddr):
            if list_node_vaddr[idx + 1] - list_node_vaddr[idx] < 512:
                dict_node_to_rn[node_vaddr] = list_node_vaddr[idx + 1]

        dict_node_to_rp[node_vaddr] = set()
        right_ptr_addr = node_vaddr + dict_node_vaddr_to_size[node_vaddr]
        while right_ptr_addr in set_ptr:
            dest = dict_ptr_to_dest[right_ptr_addr]
            try_time = SEARCH_LEN
            while dest not in set_node_addr and try_time > 0:
                dest -= 1
                try_time -= 1
            if dest in set_node_addr:
                dict_node_to_rp[node_vaddr].add(dest)
            right_ptr_addr += WORD_SIZE

        dict_node_to_lp[node_vaddr] = set()
        left_ptr_addr = node_vaddr - WORD_SIZE  # 8B
        while left_ptr_addr in set_ptr:
            dest = dict_ptr_to_dest[left_ptr_addr]
            try_time = SEARCH_LEN
            while dest not in set_node_addr and try_time > 0:
                dest -= 1
                try_time -= 1
            if dest in set_node_addr:
                dict_node_to_lp[node_vaddr].add(dest)
            left_ptr_addr -= WORD_SIZE
    return dict_node_to_ln, dict_node_to_rn, dict_node_to_lp, dict_node_to_rp

def get_train_subset_seg(set_node_init, dict_node_to_ln, dict_node_to_rn, dict_node_to_lp, dict_node_to_rp):
    set_node_addr_minibatch = set_node_init
    set_search_addr = set_node_addr_minibatch
    for t in range(100):
        set_new_addr = set()
        for addr in set_search_addr:
            #ln = rn = None
            if addr in dict_node_to_ln:
                ln = dict_node_to_ln[addr]
                if ln not in set_node_addr_minibatch:
                    set_new_addr.add(ln)
            if addr in dict_node_to_rn:
                rn = dict_node_to_rn[addr]
                if rn not in set_node_addr_minibatch:
                    set_new_addr.add(rn)
            pns = dict_node_to_rp[addr].union(dict_node_to_lp[addr])
            for pn in pns:
                if pn not in set_node_addr_minibatch:
                    set_new_addr.add(pn)
            if len(set_node_addr_minibatch) + len(set_new_addr) >= MAX_NODE_COUNT:
                break
        set_node_addr_minibatch.update(set_new_addr)
        if len(set_node_addr_minibatch) >= MAX_NODE_COUNT:
            break
        set_search_addr = set(set_new_addr)
    return set_node_addr_minibatch

def get_node_vector_seg(image_path, list_node_vaddr, dict_node_vaddr_to_size):
    dict_node_vaddr_to_content = {}
    dict_node_paddr_to_size = {}
    log('len(list_node_vaddr): ' + str(len(list_node_vaddr)))
    for node_vaddr in list_node_vaddr:
        node_paddr = vaddr_to_paddr(node_vaddr)
        if node_paddr != None:
            node_size = dict_node_vaddr_to_size[node_vaddr]
            dict_node_paddr_to_size[node_paddr] = node_size
    list_node_paddr = dict_node_paddr_to_size.keys()
    list_node_paddr.sort()#len(list_node_paddr) == len(list_node_vaddr))
    cl = 1
    with open(image_path, 'r') as image:
        for node_paddr in list_node_paddr:
            image.seek(node_paddr)
            node_content = image.read(dict_node_paddr_to_size[node_paddr])   
            node_content = [ord(c) for c in node_content]   # ord('a') = 97
            node_vaddr = paddr_to_vaddr(node_paddr)
            if node_vaddr != None:
                try:
                    dict_node_vaddr_to_content[node_vaddr] = node_content
                except MemoryError as e:
                    print (e)
                    break
    log('len(dict_node_vaddr_to_content): ' + str(len(dict_node_vaddr_to_content)))
    return dict_node_vaddr_to_content

def read_available_pages(image_name):
    #image_name = image_name.split('.mutate')[0]
    global g_dict_paddr_to_vaddr
    global g_dict_vaddr_to_paddr
    dict_paddr_to_size = {}
    set_vaddr_page = set()
    with open(PAGE_PATH + image_name + '.pages', 'r') as page:
        for line in page:
            s = line.strip().split('\t')
            vaddr = int(s[0])
            paddr = int(s[1])
            size = int(s[2])
            dict_paddr_to_size[paddr] = size
            for i in range(0, size, 4096):
                g_dict_paddr_to_vaddr[paddr + i] = vaddr + i
                g_dict_vaddr_to_paddr[vaddr + i] = paddr + i
                set_vaddr_page.add(vaddr + i)
    return dict_paddr_to_size, set_vaddr_page
    
def read_label_file(image_name, set_vaddr_type_size, set_type, type):
    with open(OBJECT_PATH + image_name + '.' + type, 'r') as f:
        for line in f:
            s = line.strip().split('\t')
            vaddr = int(s[0], 0)
            obj_type = s[1]
            if obj_type not in OBJ_TYPES:
                continue
            obj_size = int(s[2])
            if obj_type not in set_type:
                set_type.add(obj_type)
            record = (vaddr, obj_type, obj_size)
            if record not in set_vaddr_type_size:
                set_vaddr_type_size.add(record)

def get_vaddr_to_label(image_name, set_node_vaddr):
    #image_name = image_name.split('.mutate')[0]
    dict_vaddr_to_label = {}
    set_vaddr_type_size = set()
    set_type = set()
    read_label_file(image_name, set_vaddr_type_size, set_type, 'objects')
    #read_label_file(image_name, set_vaddr_type_size, set_type, 'handles')
    #print(len(set_vaddr_type_size))
    for vaddr, obj_type, obj_size in set_vaddr_type_size:
        for i in range(obj_size):
            if vaddr + i in set_node_vaddr:
                dict_vaddr_to_label[vaddr + i] = obj_type + '@' + str(i)
    return dict_vaddr_to_label, set_type

def set_to_string(set_x):
    return str([hex(x) for x in set_x]).replace('[]','').replace('[\'','').replace('\']','').replace('\', \'',',')

def list_to_str(l):
    out = ''
    for x in l:
        out += str(x) + ' '
    return out.strip()

def get_obj_list(path, obj_type):
    obj_list = {}
    f = open(path, 'r')
    for line in f:
        line = line.strip()
        s = line.split('\t')
        if s[0] == obj_type:
            obj_offset = int(s[1])
            obj_type = s[0]
            obj_size = int(s[2])
            obj_list[obj_offset] = (obj_type, obj_size)
    f.close()
    return obj_list

def is_valid_pointer_64(buf, idx, set_vaddr_page):
    if ord(buf[idx+7]) == 0xff and ord(buf[idx+6]) == 0xff and ord(buf[idx+5]) > 0x88 and ord(buf[idx]) % 4 == 0:
        dest = (ord(buf[idx+7]) << 56) + (ord(buf[idx+6]) << 48) + (ord(buf[idx+5]) << 40) + (ord(buf[idx+4]) << 32) + (ord(buf[idx+3]) << 24) + (ord(buf[idx+2]) << 16) + (ord(buf[idx+1]) << 8) + ord(buf[idx])
        if (dest >> 12 << 12) in set_vaddr_page:#di 12 wei qing0
            return dest
    return None

def get_pointer_to_dest(image_path, dict_paddr_to_size, set_vaddr_page):
    dict_vaddr_to_dest = {}
    list_paddr = dict_paddr_to_size.keys()
    list_paddr.sort()
    with open(image_path, 'r') as image:
        for paddr in list_paddr:
            page_size = dict_paddr_to_size[paddr]
            try:
                image.seek(paddr)
            except IOError as e:
                print(e)
                print(paddr)
                continue
            page_content = image.read(page_size)
            if len(page_content) == 0:
                continue
            for offset in range(0, len(page_content), WORD_SIZE):
                dest = is_valid_pointer_64(page_content, offset, set_vaddr_page)
                if dest != None:
                    dict_vaddr_to_dest[paddr_to_vaddr(paddr + offset)] = dest   # dest is also vaddr!
    return dict_vaddr_to_dest

def paddr_to_vaddr(paddr):
    if paddr >> 12 << 12 in g_dict_paddr_to_vaddr:
        return g_dict_paddr_to_vaddr[paddr >> 12 << 12] + paddr % 4096
    else:
        return None

def vaddr_to_paddr(vaddr):
    if vaddr >> 12 << 12 in g_dict_vaddr_to_paddr:
        return g_dict_vaddr_to_paddr[vaddr >> 12 << 12] + vaddr % 4096
    else:
        return None

def log(message):
    print('%s\t%s' %(strftime("%Y-%m-%d %H:%M:%S", gmtime()), message))
    sys.stdout.flush()

if __name__ == "__main__":
    main()
