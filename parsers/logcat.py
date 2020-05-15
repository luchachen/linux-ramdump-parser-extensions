from print_out import print_out_str
from parser_util import register_parser, RamParser, cleanupString
from mmu import MMU, Armv8MMU
import rb_tree
import struct
import time
import local_settings
import gdbmi

@register_parser('--alogcat', 'Print the logcat', shortopt=None)
class ALogcat(RamParser):

    def parse(self):
        try:
            self.gdbmi = gdbmi.GdbMI(self.ramdump.gdb_path, local_settings.logd_path)
            self.gdbmi.open()
        except:
            print_out_str('Error: Please set your logd_path in local_settings.py.\n'
                    + 'It is at ${ANDORID_ROOT}/out/target/product/${TARGET_PRODUCT}/symbols/system/bin/logd')
            return

        self.log_file = self.ramdump.open_file("logcat.txt")
        self.find_mm(self.ramdump)
        self.find_load_bias(self.ramdump)
        self.dump_args(self.ramdump, self.mm_addr)
        self.dump_vmas(self.ramdump, self.mm_addr)
        self.dump_logcat()
        print_out_str('---wrote logcat to logcat.txt')
        self.log_file.close()

    def __del__(self):
        try:
            self.gdbmi.close()
        except:
            pass

    def find_mm(self, ramdump):
        thread_addr = None
        offset_comm = ramdump.field_offset('struct task_struct', 'comm')
        for task in ramdump.for_each_process():
            task_name = cleanupString(ramdump.read_cstring(task + offset_comm, 16))
            if task_name == 'logd':
                for thread in ramdump.for_each_thread(task):
                    thread_name = cleanupString(ramdump.read_cstring(thread + offset_comm, 16))
                    if thread_name == 'logd.writer':
                        thread_addr = thread
                        break
                break

        if not thread_addr:
            print_out_str("!!!No logd.writer service found !\n")
            return

        mm_addr = ramdump.read_structure_field(
                thread_addr, 'struct task_struct', 'mm')

        pgd_addr = ramdump.read_structure_field(
                mm_addr, 'struct mm_struct', 'pgd')

        pgd_addr = ramdump.virt_to_phys(pgd_addr)
        self.mmu = type(ramdump.mmu)(ramdump, pgd_addr)
        self.mm_addr = mm_addr

    def find_load_bias(self, ramdump):
        virt_start_code = ramdump.read_structure_field(
                self.mm_addr, 'struct mm_struct', 'start_code')
        self.load_bias = virt_start_code

    def dump_args(self, ramdump, mm):
        names = (
                ("env_start", "env_end"),
                ("arg_start", "arg_end"),
                ("start_stack", ""),
                ("start_brk", "brk"),
                ("start_data", "end_data"),
                ("mmap_base", ""),
                ("start_code", "end_code"),
                )
        print_out_str("{:10}\t{:8}\t{:8}".format("name", "virt", "phys"))
        print_out_str("----------------------------------")
        for start,end in names:
            if len(end) > 0:
                virt = ramdump.read_structure_field(
                        mm, 'struct mm_struct', end)
                phys = self.mmu.virt_to_phys(virt) or 0
                print_out_str("{:10}\t0x{:08x}\t0x{:08x}".format(end, virt, phys))

            if len(start) > 0:
                virt = ramdump.read_structure_field(
                        mm, 'struct mm_struct', start)
                phys = self.mmu.virt_to_phys(virt) or 0
                print_out_str("{:10}\t0x{:08x}\t0x{:08x}".format(start, virt, phys))

            print_out_str("----------------------------------")

    def dump_vmas(self, ramdump, mm):
        def mm_rb_func(node, extra):
            vm_start = self.ramdump.read_u32(self.ramdump.sibling_field_addr(
                node, 'struct vm_area_struct', 'vm_rb', 'vm_start'))
            vm_end = self.ramdump.read_u32(self.ramdump.sibling_field_addr(
                node, 'struct vm_area_struct', 'vm_rb', 'vm_end'))
            vm_flags = self.ramdump.read_u32(self.ramdump.sibling_field_addr(
                node, 'struct vm_area_struct', 'vm_rb', 'vm_flags'))
            vm_pgoff= self.ramdump.read_u32(self.ramdump.sibling_field_addr(
                node, 'struct vm_area_struct', 'vm_rb', 'vm_pgoff'))
            vm_ops = self.ramdump.read_u32(self.ramdump.sibling_field_addr(
                node, 'struct vm_area_struct', 'vm_rb', 'vm_ops'))
            print_out_str("{:08x}-{:08x} {:08x} {:08x} {:08x}".format(vm_start, vm_end, vm_flags, vm_pgoff, vm_ops))

        offset_mm_rb = ramdump.field_offset('struct mm_struct', 'mm_rb')
        root = ramdump.read_word(mm + offset_mm_rb)
        rb_walker = rb_tree.RbTreeWalker(self.ramdump)
        rb_walker.walk(root, mm_rb_func)

    def read_word(self, addr):
        return self.ramdump.read_word(self.mmu.virt_to_phys(addr), False)

    def read_u16(self, addr):
        return self.ramdump.read_u16(self.mmu.virt_to_phys(addr), False)

    def read_u32(self, addr):
        return self.ramdump.read_u32(self.mmu.virt_to_phys(addr), False)

    def read_u64(self, addr):
        return self.ramdump.read_u64(self.mmu.virt_to_phys(addr), False)

    def read_byte(self, addr):
        return self.ramdump.read_byte(self.mmu.virt_to_phys(addr), False)

    def read_structure_field(self, addr, struct_name, field):
        size = self.gdbmi.sizeof("(({0} *)0)->{1}".format(struct_name, field))
        if addr is None or size is None:
            return None

        addr += self.gdbmi.field_offset(struct_name, field)
        if size == 1:
            return self.read_byte(addr)
        if size == 2:
            return self.read_u16(addr)
        if size == 4:
            return self.read_u32(addr)
        if size == 8:
            return self.read_u64(addr)
        return None

    def dump_logcat(self):
        ramdump = self.ramdump
        log_file = self.log_file

        logBuf = self.read_word(self.load_bias + self.gdbmi.address_of('logBuf'))
        if not logBuf:
            log_file.write("The heap has been swapped out !!!\n")
            return

        logBufPhys = self.mmu.virt_to_phys(logBuf)
        if logBufPhys == 0:
            log_file.write("The logcat buffer has been swapped out !!!\n")
            return

        logIdMap = ["MAIN", "RADIO", "EVENTS", "SYSTEM", "CRASH", "STATS", "KERNEL"]

        '''
        class LogBuffer {
            LogBufferElementCollection mLogElements;
            unsigned long mMaxSize[LOG_ID_MAX];
            ...
        };
        '''
        log_file.write("Buffer Size:\n")
        for i,name in enumerate(logIdMap):
            size = self.read_structure_field(logBuf, 'LogBuffer', 'mMaxSize[{}]'.format(i))
            log_file.write("{}: {}KB\n".format(name, size / 1024))

        mLogElements = logBuf + self.gdbmi.field_offset('LogBuffer', 'mLogElements')

        '''
        typedef std::list<LogBufferElement *> LogBufferElementCollection;

        std::list

                head    n1      n2      n3
           n3 <-|prev <-|prev <-|prev <-|prev
                |next ->|next ->|next ->|next -> head
                |len    |ptr    |ptr    |ptr

        '''
        '''
        use 'double tab' auto completion to check the LogBufferElementCollection contents

        (gdb) print sizeof(((LogBufferElementCollection *)0)->)
        __allocate_node             __move_assign               cend                        max_size                    reverse
        __copy_assign_alloc         __move_assign_alloc         clear                       merge                       size
        __end_                      __node_alloc                crbegin                     operator=                   sort
        __end_as_link               __node_alloc_max_size       crend                       pop_back                    splice
        __invalidate_all_iterators  __size_alloc_               empty                       pop_front                   swap
        __invariants                __sz                        end                         push_back                   unique
        __iterator                  __unlink_nodes              erase                       push_front                  ~__list_imp
        __link_nodes                assign                      front                       rbegin
        __link_nodes_at_back        back                        get_allocator               remove
        __link_nodes_at_front       begin                       insert                      rend
        __list_imp                  cbegin                      list                        resize
        '''
        #log_file.write("\nLogBufferElementCollection:\n")
        __prev = self.read_structure_field(mLogElements, 'LogBufferElementCollection', '__end_.__prev_')
        __next = self.read_structure_field(mLogElements, 'LogBufferElementCollection', '__end_.__next_')
        #log_file.write("prev: 0x{:08x}\n".format(__prev))
        #log_file.write("next: 0x{:08x}\n".format(__next))
        collectionLen = self.read_word(mLogElements + self.gdbmi.sizeof('((LogBufferElementCollection *)0)->__end_'))
        #log_file.write("len: {}\n".format(collectionLen))

        currPtr = headPtr = mLogElements
        LogBufferElementCollection = []
        for i in range(0, collectionLen+1):
            currPtr = self.read_structure_field(currPtr, 'LogBufferElementCollection', '__end_.__next_')
            if currPtr == headPtr:
                break
            LogBufferElementCollection.append(currPtr)
        else:
            log_file.write("ERROR: iter list\n")
            return

        logcat = []
        for i,node in enumerate(LogBufferElementCollection):
            entry = {}

            LogBufferElement = self.read_word(node + self.gdbmi.sizeof('((LogBufferElementCollection *)0)->__end_'))

            '''
            class LogBufferElement {
                const uid_t mUid;
                const pid_t mPid;
                const pid_t mTid;
                char *mMsg;
                union {
                    const unsigned short mMsgLen; // mMSg != NULL
                    unsigned short mDropped;      // mMsg == NULL
                };
                const uint8_t mLogId;
                const log_time mRealTime;
                static atomic_int_fast64_t sequence;
                ...
            '''
            #mLogId
            mLogId = self.read_structure_field(LogBufferElement, 'LogBufferElement', 'mLogId')
            if not mLogId in range(0, len(logIdMap)):
                continue
            entry["id"] = logIdMap[mLogId]

            #mPid
            mPid = self.read_structure_field(LogBufferElement, 'LogBufferElement', 'mPid')
            entry["pid"] = mPid

            #mTid
            mTid = self.read_structure_field(LogBufferElement, 'LogBufferElement', 'mTid')
            entry["tid"] = mTid

            '''
            struct log_time {
                uint32_t tv_sec;
                uint32_t tv_nsec;
            }
            '''
            #mRealTime
            rt_sec = self.read_structure_field(LogBufferElement, 'LogBufferElement', 'mRealTime.tv_sec')
            rt_nsec = self.read_structure_field(LogBufferElement, 'LogBufferElement', 'mRealTime.tv_nsec')
            mRealTime = rt_sec + rt_nsec/1000000000.0
            entry["time"] = mRealTime

            #mMsg
            mMsg = self.read_structure_field(LogBufferElement, 'LogBufferElement', 'mMsg')
            mMsgLen = self.read_structure_field(LogBufferElement, 'LogBufferElement', 'mMsgLen')
            if mMsgLen == 0:
                continue

            physAddr = self.mmu.virt_to_phys(mMsg)
            msg = ramdump.read_physical(physAddr, mMsgLen)
            if msg == None or len(msg) == 0:
                continue

            '''
            msg format: <priority:1><tag:N>\0<message:N>\0
            '''
            priorityMap = ["UNKNOWN", "DEFAULT", "VERBOSE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "SILENT"]
            priority = struct.unpack("<B", msg[0])[0]
            if priority >= len(priorityMap):
                continue

            entry["priority"] = priorityMap[priority][0]

            result = msg[1:].split("\0", 1)
            if len(result) == 1:
                tag = ""
                message = result[0].rstrip("\0\n")
            else:
                tag = result[0]
                message = result[1].rstrip("\0\n")

            entry["tag"] = tag
            entry["message"] = message

            logcat.append(entry)

        logcat.sort(key = lambda x : x["time"])

        log_file.write("\n+++\n")
        for entry in logcat:
            msg = "{: <6} {}.{:03.0f} {}:{} {} {}: {}\n".format(
                    entry["id"],
                    time.strftime("%m-%d %T", time.localtime(entry["time"])),
                    entry["time"]%1*1000,
                    entry["pid"],
                    entry["tid"],
                    entry["priority"],
                    entry["tag"],
                    entry["message"]
                    )
            log_file.write(msg)
        log_file.write("\n---\n")

