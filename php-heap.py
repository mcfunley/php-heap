"""
  php-heap - gdb extensions for debugging and analyzing the PHP heap.
  Copyright (C) 2010 Dan McKinley

  -----  
  Usage:

  How this works:

  -----

  Basics about PHP memory:

  Basics about PHP types:

  Some important places to refer to in the PHP sources:
  
  -----

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
import gdb
import sys


### The zval datatypes. 

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


### Definitions for types, their corresponding pointer types, and shortcuts
### for casts.

# These are the most fundamental unit of the heap. 
block_type = gdb.lookup_type('zend_mm_block')
blockptr_type = block_type.pointer()
def blockptr(x): return x.cast(blockptr_type)

voidptr_type = gdb.lookup_type('void').pointer()
def voidptr(x): return x.cast(voidptr_type)

charptr_type = gdb.lookup_type('char').pointer()
def charptr(x): return x.cast(charptr_type)

object_type = gdb.lookup_type('zend_object')
objectptr_type = object_type.pointer()
def objptr(x): return x.cast(objectptr_type)

zval_type = gdb.lookup_type('zval')
zvalptr_type = zval_type.pointer()
def zvalptr(x): return x.cast(zvalptr_type)

# aka arrays.
hashtable_type = gdb.lookup_type('HashTable')
hashtableptr_type = hashtable_type.pointer()
def hashtableptr(x): return x.cast(hashtableptr_type)

# Storage unit for hash tables. 
bucket_type = gdb.lookup_type('Bucket')
bucketptr_type = bucket_type.pointer()
def bucketptr(x): return x.cast(bucketptr_type)


### This is a recreation of the alignment calculations in zend_alloc.c. 
### These constants and functions are used to compute block locations. 

zend_mm_alignment = 8
zend_mm_alignment_mask = ~(zend_mm_alignment - 1)

zend_mm_type_mask = 0x03L


def zend_mm_aligned_size(size):
    return ((size + zend_mm_alignment - 1) & zend_mm_alignment_mask)


def aligned_struct_size(name):
    return zend_mm_aligned_size(gdb.lookup_type(name).sizeof)


zend_mm_aligned_segment_size = aligned_struct_size('zend_mm_segment')
zend_mm_aligned_header_size = aligned_struct_size('zend_mm_block')


### Methods for navigating blocks on the heap and retrieving their data.

def zend_mm_data_of(blockptr):
    return voidptr(charptr(blockptr) + zend_mm_aligned_header_size)


def zend_mm_block_size(blockptr):
    block = blockptr.dereference()
    return block['info']['_size'] & (~zend_mm_type_mask)


def zend_mm_next_block(block):
    return zend_mm_block_at(block, zend_mm_block_size(block))


def zend_mm_block_at(block, offset):
    return blockptr(charptr(block) + offset)


# Constants used to track the status of a particular block. 
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
    """
    Command that scans the entire heap and performs an analysis of usage. 
    
    Call with no arguments. 
      
      (gdb) php-heap-diag
    
    """
    def __init__(self):
        gdb.Command.__init__(self, 'php-heap-diag', gdb.COMMAND_DATA) 


    def reset_stats(self):
        """
        Resets the statistics stored as instance fields. Called before 
        an invocation of the command. 
        """
        self.block_count = 0
        self.free_block_count = 0
        self.free_space = 0
        self.used_block_count = 0
        self.used_space = 0
        self.fragmentation_space = 0
        self.largest_free_block = 0
        self.zval_counts = {}
        self.zval_sizes = {}
        self.class_counts = {}


    def invoke(self, arg, from_tty):
        """
        Runs the command.
        """
        self.reset_stats()

        self.frame = gdb.selected_frame()
        alloc_globals = self.frame.read_var('alloc_globals')
        self.heap = alloc_globals['mm_heap'].dereference()
        self.eg = self.frame.read_var('executor_globals')

        self.visit_all_blocks()

        self.print_stats()


    def print_stats(self):
        """
        Prints the heap statistics collected during the run. 
        """
        print 'Real size:', self.human_size_bytes(self.heap['real_size'])
        print 'Peak size:', self.human_size_bytes(self.heap['real_peak'])
        print 'Memory limit:', self.human_size_bytes(self.heap['limit'])
        print
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
        self.print_counts('instances', self.class_counts)
        print
        self.print_counts('zval types', self.zval_counts, self.zval_sizes)


    def print_counts(self, label, counts, sizes = None):
        """
        Prints out a table given dictionaries of counts and total sizes. 
        The keys in the two dictionaries should match. The sizes are optional.
        The label parameter indicates what the keys represents. 
        """
        if not sizes:
            sizes = {}

        fmt = '%-40s%-10s  %-10s'
        print fmt % (label, 'count', 'size')
        print fmt % (len(label)*'-', '-----', '----')

        cs = [(n, c) for n, c in counts.items()]

        csum, ssum = 0, 0
        for n, c in reversed(sorted(cs, key=lambda (_, c): c)):
            size = sizes.get(n, -1)
            csum += c
            ssum += max(size, 0)
            size = self.human_size_bytes(size) if size > 0 else ''

            print fmt % (n, c, size)
            
        print fmt % ('', '-'*10, '-'*10)
        print fmt % ('Total:', csum, self.human_size_bytes(ssum))


    def visit_all_blocks(self):
        """
        Walks the entire heap, collecting stats. 
        """
        self.log('Analyzing heap ')

        # The heap is implemented as a linked list of segments, each 
        # containing a contiguous list of blocks. 
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
        """
        Walks each block in the given segment, collecting stats. 
        """
        p = blockptr(charptr(seg) + zend_mm_aligned_segment_size)
        while 1:
            self.visit_block(p)

            q = zend_mm_next_block(p)

            # simple integrity check - see zend_check_heap for more 
            # rigorous check.
            if q.dereference()['info']['_prev'] != blocksize(p):
                print 'Heap corrupted - size field does not match previous'

            # the segment is terminated by a special guard block. 
            if zend_mm_is_guard_block(q):
                return

            p = q


    def visit_block(self, blockptr):
        """
        Aggregates statistics given a single block. 
        """
        self.block_count += 1

        used_size = self.count_block_size(blockptr)

        if used_size < 0:
            # free block
            return 

        # Based on the size of the used portion of the block, make a guess
        # about what it contains (generally you can guess that it's a zval
        # this way with a high degree of accuracy). 

        data = zend_mm_data_of(blockptr)
        if used_size == zval_type.sizeof:
            self.visit_zval(data.cast(zvalptr_type).dereference())

        # todo other things?


    def count_block_size(self, blockptr):
        """
        Given a block, tracks its free or used space. If the block is in use,
        this also tracks the amount of fragmentation in the unused portion of
        the block. Also keeps track of some aggregated statistics. 

        Returns the count of bytes in the block that are in use (not counting 
        the block header). 
        """
        size = blocksize(blockptr)

        if zend_mm_is_free_block(blockptr):
            self.free_block_count += 1
            self.free_space += size
            if size > self.largest_free_block:
                self.largest_free_block = size
            return -1
            
        self.used_block_count += 1
        self.used_space += size

        # There will be fragmentation loss at the end of the block if the
        # free block was larger than what was requested, but too small to 
        # accomodate an additional header and minimum amount of data. 
        block = blockptr.dereference()
        used_size = block['debug']['size']
        self.fragmentation_space += size - used_size - block_type.sizeof
        return used_size


    def visit_zval(self, zval):
        """
        Aggregates statistics given a single zval. 
        """
        datatype = datatypes.get(int(zval['type']), 'unknown')
        self.zval_counts[datatype] = self.zval_counts.get(datatype, 0) + 1

        zs = zval_type.sizeof
        if datatype == 'object':
            self.visit_object_value(zval['value']['obj'])
            size = 0 # todo
        elif datatype == 'string':
            size = int(zval['value']['str']['len']) + zs
        elif datatype in ('array', 'constant_array'):
            size = self.hashtable_size(zval['value']['ht'].dereference()) + zs
        else:
            # the value types are stored within the zval. 
            size = zs

        self.zval_sizes[datatype] = self.zval_sizes.get(datatype, 0) + size


    def hashtable_size(self, ht):
        # the type contained within the hash table can be inferred from the 
        # destructor function pointer
        dtor = ht['pDestructor']
        if 'zval_ptr_dtor' in str(dtor):
            pass
        else:
            print 'unknown array', dtor
        return -1000


    def get_objectptr(self, zobj):
        """
        Gets a zend_object* given a zend_object_value structure. (The struct 
        contains an object handle that has to be mapped to the real address.)
        """
        # The handle is used as a simple offset in a global object table, kept
        # in the executor_globals. The entry in the table has the pointer.
        handle = int(zobj['handle'])
        buckets = self.eg['objects_store']['object_buckets']
        bucket = (buckets + handle).dereference()['bucket']
        return objptr(bucket['obj']['object'])


    def visit_object_value(self, zobj):
        """
        """
        zend_object_ptr = self.get_objectptr(zobj)
        ce = zend_object_ptr.dereference()['ce']
        name = ce['name'].string()
        self.class_counts[name] = self.class_counts.get(name, 0) + 1


    def human_size_bytes(self, val):
        for x in [' bytes','KB','MB','GB',]:
            if val < 1024.0:
                return "%3.1f%s" % (val, x)
            val /= 1024.0
                    

diag = PHPHeapDiag()
diag.invoke('', '')
