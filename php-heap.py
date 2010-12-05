import gdb
import sys


datatypes = {
    0: 'null',
    1: 'long', 
    2: 'double',
    3: 'bool',
    4: 'array',
    5: 'object',
    6: 'string',
    7: 'resource',
    8: 'constant',
    9: 'constant_array',
    }


zend_mm_alignment = 8
zend_mm_alignment_mask = ~(zend_mm_alignment - 1)

zend_mm_type_mask = 0x03L

block_type = gdb.lookup_type('zend_mm_block')
voidptr_type = gdb.lookup_type('void').pointer()
charptr_type = gdb.lookup_type('char').pointer()
blockptr_type = block_type.pointer()

object_type = gdb.lookup_type('zend_object')
objectptr_type = object_type.pointer()

zval_type = gdb.lookup_type('zval')
zvalptr_type = zval_type.pointer()



def blockptr(x):
    return x.cast(blockptr_type)


def charptr(x):
    return x.cast(charptr_type)


def voidptr(x):
    return x.cast(voidptr_type)


def objptr(x):
    return x.cast(objectptr_type)


def zend_mm_aligned_size(size):
    return ((size + zend_mm_alignment - 1) & zend_mm_alignment_mask)


def aligned_struct_size(name):
    return zend_mm_aligned_size(gdb.lookup_type(name).sizeof)


zend_mm_aligned_segment_size = aligned_struct_size('zend_mm_segment')
zend_mm_aligned_header_size = aligned_struct_size('zend_mm_block')


def zend_mm_data_of(blockptr):
    return voidptr(charptr(blockptr) + zend_mm_aligned_header_size)


def zend_mm_block_size(blockptr):
    block = blockptr.dereference()
    return block['info']['_size'] & (~zend_mm_type_mask)


def zend_mm_next_block(block):
    return zend_mm_block_at(block, zend_mm_block_size(block))


def zend_mm_block_at(block, offset):
    return blockptr(charptr(block) + offset)


zend_mm_free_block = 0x00L
zend_mm_used_block = 0x01L
zend_mm_guard_block = 0x03L


def blocksize(blockptr):
    return blockptr.dereference()['info']['_size']


def zend_mm_is_free_block(blockptr):
    return not (blocksize(blockptr) & zend_mm_used_block)


def zend_mm_is_used_block(blockptr):
    return blocksize(blockptr) & zend_mm_used_block


def zend_mm_is_guard_block(blockptr):
    return blocksize(blockptr) & zend_mm_type_mask == zend_mm_guard_block



class PHPHeapDiag(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'php-heap-diag', gdb.COMMAND_DATA) 


    def reset_stats(self):
        self.block_count = 0
        self.free_block_count = 0
        self.free_space = 0
        self.used_block_count = 0
        self.used_space = 0
        self.fragmentation_space = 0
        self.largest_free_block = 0
        self.zval_counts = {}
        self.class_counts = {}


    def invoke(self, arg, from_tty):
        self.reset_stats()

        self.frame = gdb.selected_frame()
        alloc_globals = self.frame.read_var('alloc_globals')
        self.heap = alloc_globals['mm_heap'].dereference()
        self.eg = self.frame.read_var('executor_globals')

        self.visit_all_blocks()

        self.print_overall_stats()
        self.print_block_stats()


    def print_block_stats(self):
        print 'Block count:', self.block_count
        print 'Free blocks:', self.free_block_count
        print 'Free space:', self.human_size_bytes(self.free_space)
        print 'Largest free block:', self.human_size_bytes(
            self.largest_free_block)
        print 'Used blocks:', self.used_block_count
        print 'Used space:', self.human_size_bytes(self.used_space)
        print 'Fragmentation loss:', self.human_size_bytes(
            self.fragmentation_space)
        print
        print 'Instance counts:'
        self.print_counts(self.class_counts)
        print
        print 'zval types:'
        self.print_counts(self.zval_counts)


    def print_counts(self, d):
        cs = [(n, c) for n, c in d.items()]
        i = 0
        for n, c in reversed(sorted(cs, key=lambda (_, c): c)):
            print '%s:' % n, c
            if i > 10:
                return
            i += 1


    def visit_all_blocks(self):
        self.log('Analyzing heap ')
        seg = self.heap['segments_list']
        while seg:
            self.visit_segment(seg)
            seg = seg['next_segment']
            self.log('.')
        print ' done.'
        print


    def log(self, x):
        sys.stdout.write(x)
        sys.stdout.flush()


    def visit_segment(self, seg):
        p = blockptr(charptr(seg) + zend_mm_aligned_segment_size)
        while 1:
            self.visit_block(p)

            q = zend_mm_next_block(p)

            # simple integrity check - see zend_check_heap for more 
            # rigorous check.
            if q.dereference()['info']['_prev'] != blocksize(p):
                print 'Heap corrupted - size field does not match previous'

            if zend_mm_is_guard_block(q):
                return

            p = q


    def visit_block(self, blockptr):
        self.block_count += 1
        
        size = blocksize(blockptr)

        if zend_mm_is_free_block(blockptr):
            self.free_block_count += 1
            self.free_space += size
            if size > self.largest_free_block:
                self.largest_free_block = size
            return
            
        self.used_block_count += 1
        self.used_space += size

        # There will be fragmentation loss at the end of the block if the
        # free block was larger than what was requested, but too small to 
        # accomodate an additional header and minimum amount of data. 
        block = blockptr.dereference()
        used_size = block['debug']['size']
        self.fragmentation_space += size - used_size - block_type.sizeof

        data = zend_mm_data_of(blockptr)
        if used_size == zval_type.sizeof:
            self.visit_zval(data.cast(zvalptr_type).dereference())

        # todo other things?


    def visit_zval(self, zval):
        datatype = datatypes.get(int(zval['type']), 'unknown')
        self.zval_counts[datatype] = self.zval_counts.get(datatype, 0) + 1

        if datatype == 'object':
            self.visit_object_value(zval['value']['obj'])

        # todo other types


    def get_objectptr(self, zobj):
        handle = int(zobj['handle'])
        buckets = self.eg['objects_store']['object_buckets']
        bucket = (buckets + handle).dereference()['bucket']
        return objptr(bucket['obj']['object'])


    def visit_object_value(self, zobj):
        zend_object_ptr = self.get_objectptr(zobj)
        ce = zend_object_ptr.dereference()['ce']
        name = ce['name'].string()
        self.class_counts[name] = self.class_counts.get(name, 0) + 1


    def human_size_bytes(self, val):
        for x in ['bytes','KB','MB','GB',]:
            if val < 1024.0:
                return "%3.1f%s" % (val, x)
            val /= 1024.0
            

    def print_overall_stats(self):
        print 'Real size:', self.human_size_bytes(self.heap['real_size'])
        print 'Peak size:', self.human_size_bytes(self.heap['real_peak'])
        print 'Memory limit:', self.human_size_bytes(self.heap['limit'])
        print
        

diag = PHPHeapDiag()
diag.invoke('', '')
