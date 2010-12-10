"""
  php-heap - gdb extensions for debugging and analyzing the PHP heap.
  Copyright (C) 2010 Dan McKinley

  -----  
  
  For usage, setup, etc, please see the README. 

  -----

  Basics about PHP memory:

    PHP maintains a heap for scripts, implemented as a linked list of segments,
    divided into blocks given to individual allocations. There is a free list
    as well as some other optimizations around finding free blocks, mostly not
    pertinent to this tool. 

    Segments are allocated as needed, up to the configured memory limit. 

    This tool walks through each segment, counting up the memory for each block 
    that is in use. 

  Basics about PHP types:

    The fundamental PHP type is the zvalue. This is a variant type that holds 
    either a primitive type or a reference to another type somewhere else on 
    the heap. 
    
    The only extended values allowed are arrays (called HashTables in the PHP
    source) and objects. From the point of view of the allocator, objects are 
    just hash tables of properties and a pointer to a class. (The class does
    not count against a script's memory footprint, but of course the properties 
    do). 

    Objects within zvals have an extra level of indirection. The zval has an 
    object handle, which indexes the objects_store in the executor_globals. 
    The objects_store entry then points at the real value of the object. 

  Some important places to refer to in the PHP sources:

    * zend_alloc.c / zend_alloc.h 
        Allocator, definitions of segments and blocks, and important constants
        and #defines for walking around the heap.

    * zend.h
        Definitions of zvals and class entries. 

    * zend_types.h
        Has zend_object_value, embedded inside of zvals for objects. 

    * zend_objects_API.h
        Definition of the objects_store and its buckets. 

    * zend_hash.c / zend_hash.h
        Hashtables, aka PHP arrays. 
  
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
import itertools


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

char_type = gdb.lookup_type('char')
charptr_type = char_type.pointer()
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

unsigned_int_type = gdb.lookup_type('unsigned int')

zend_object_store_bucket_type = gdb.lookup_type('zend_object_store_bucket')
zend_object_store_bucketptr_type = zend_object_store_bucket_type.pointer()
def zend_object_store_bucketptr(x):
    return x.cast(zend_object_store_bucketptr_type)



### figure out if this is a debug mode build or not, and so on (affects the 
### values of some constants).

try:
    _debug_info_type = gdb.lookup_type('zend_mm_debug_info')
except RuntimeError:
    zend_debug = 0
    zend_mm_heap_protection = 0
else:
    _fields = [x.name for x in _debug_info_type.strip_typedefs().fields()]
    zend_mm_heap_protection = 'start_magic' in _fields
    zend_debug = 'filename' in _fields


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

end_magic_size = unsigned_int_type.sizeof if zend_mm_heap_protection else 0

zend_mm_min_alloc_block_size = zend_mm_aligned_size(
    zend_mm_aligned_header_size + end_magic_size)

try:
    zend_mm_aligned_free_header_size = \
        aligned_struct_size('zend_mm_small_free_block')
except RuntimeError:
    # the compiler seems to optimize the _small variant out
    zend_mm_aligned_free_header_size = \
        aligned_struct_size('zend_mm_free_block')

zend_mm_aligned_min_header_size = max(
    zend_mm_aligned_free_header_size,
    zend_mm_min_alloc_block_size)


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



def human_size_bytes(val):
    """
    Returns a human-legible string for the given byte count. 
    """
    for x in [' bytes','KB','MB','GB',]:
        if val < 1024.0:
            return "%3.1f%s" % (float(val), x)
        val /= 1024.0



def arg_to_address(arg):
    """
    Returns an address, given a string argument to a gdb.Function.
    """
    if 'x' in arg:
        return long(arg, 16)
    return long(arg)



class Proxy(object):
    def __init__(self, target):
        self.target = target

    def __getattr__(self, k):
        if not hasattr(self, k):
            return getattr(self.target, k)
        return object.__getattr__(self, k)


    def __getitem__(self, k):
        return self.target[k]


    def __str__(self):
        return str(self.target)



class Zval(Proxy):
    def datatype(self):
        return datatypes.get(int(self['type']), 'unknown')


    def get_value(self):
        t = self.datatype()
        v = self['value']
        if t == 'long':
            return long(v['lval'])
        if t == 'double':
            return double(v['dval'])
        if t == 'string':
            return v['str']['val'].string()
        if t == 'bool':
            return 'true' if long(v['lval']) else 'false'
        if t == 'array':
            # remove the 'L'
            return hex(long(v['ht'].address))[:-1]
        
        return ''


class ZendObject(Proxy):
    def class_name(self):
        return self['ce']['name'].string()

    def iterproperties(self):
        return hashtable_buckets(self['properties'].dereference())

    
    def field_names(self):
        ps = self['ce']['properties_info']
        return [charptr(b['arKey']).string() for b in hashtable_buckets(ps)]



class HashtableBucket(Proxy):
    def data_as_zval(self):
        return zvalptr(self['pDataPtr']).dereference()


    def key(self):
        return self['arKey']

    
    def index(self):
        return self['h']


def hashtable_buckets(ht):
    """
    Given a hashtable, returns an iterator over its buckets. 
    """
    bp = ht['pListHead']
    while bp != 0:
        b = HashtableBucket(bp.dereference())
        yield b
        bp = b['pListNext']



class Accumulator(object):
    def __init__(self):
        self.reset()


    def reset(self):
        self.visited = {}
        self.object_counts = {}
        self.object_sizes = {}
        self.objects = []
        self.zval_counts = {}
        self.zval_sizes = {}


    def have_visited(self, address):
        address = long(address)
        if address in self.visited:
            return True
        self.visited[address] = 1
        return False


    def incr(self, d, k, n = 1):
        d[k] = d.get(k, 0) + n


    def remember_visited_object(self, ptr, classname, size):
        self.objects.append(ptr)


    def visited_object(self, ptr, classname, size):
        self.incr(self.object_counts, classname)
        self.incr(self.object_sizes, classname, size)
        self.remember_visited_object(ptr, classname, size)


    def visited_zval(self, ptr, typename, size):
        self.incr(self.zval_counts, typename)
        self.incr(self.zval_sizes, typename, size)


    def print_zval_table(self):
        self.print_counts('zval types', self.zval_counts, self.zval_sizes)


    def print_object_table(self):
        self.print_counts('instances', self.object_counts, self.object_sizes)


    def print_counts(self, label, counts, sizes):
        """
        Prints out a table given dictionaries of counts and total sizes. 
        The keys in the two dictionaries should match. The sizes are optional.
        The label parameter indicates what the keys represents. 
        """
        fmt = '%-40s%-10s  %-10s'
        print fmt % (label, 'count', 'size')
        print fmt % (len(label)*'-', '-----', '----')

        ss = [(n, s) for n, s in sizes.items()]

        csum, ssum = 0, 0
        for n, size in reversed(sorted(ss, key=lambda (_, s): s)):
            count = counts[n]
            csum += count
            ssum += size
            size = human_size_bytes(size) if size > 0 else ''
            print fmt % (n, count, size)
            
        print fmt % ('', '-'*10, '-'*10)
        print fmt % ('Total:', csum, human_size_bytes(ssum))
        print



class ClassAccumulator(Accumulator):
    def __init__(self, classname):
        self.classname = classname
        Accumulator.__init__(self)


    def reset(self):
        Accumulator.reset(self)
        self.sizes = {}


    def get_size(self, ptr):
        return self.sizes[long(ptr)]
    

    def remember_visited_object(self, ptr, classname, size):
        if classname == self.classname:
            Accumulator.remember_visited_object(self, ptr, classname, size)
            self.sizes[long(ptr)] = size



class Crawler(object):
    def __init__(self, accumulator = None):
        self.accumulator = accumulator or Accumulator()
        self.eg = gdb.selected_frame().read_var('executor_globals')


    def found_objects(self):
        return self.accumulator.objects

    
    def visit_voidptr(self, voidptr, size):
        if self.looks_like_zval(size, voidptr):
            self.visit_zval(zvalptr(voidptr).dereference())


    def looks_like_zval(self, size, data):
        """
        Epic kluge to guess if a data block is a zval. 
        """
        zval_size = zval_type.sizeof
        if size < zval_size:
            # the block is too small
            return False

        if size > zval_size + zend_mm_aligned_min_header_size:
            # The allocator would  have used the remainder of this 
            # space for another block. 
            return False

        # commence sniffing around inside the structure, getting 
        # increasingly more ridiculous

        zval = zvalptr(data).dereference()
        t = int(zval['type'])
        if t not in datatypes:
            return False

        if int(zval['is_ref']) not in (0, 1):
            return False
        if zval['refcount'] > 75 or zval['refcount'] < 0:
            return False

        if datatypes[t] in ('array', 'constant_array'):
            # check to see if there's a symbol for the destructor. 
            ht = zval['value']['ht'].dereference()
            dtor = ht['pDestructor']
            try:
                # kind of a shitty way to tell if pDestructor points at a symbol
                # and that symbol sounds like it's a destructor
                if 'dtor' not in str(dtor):
                    return False
            except:
                return False
        elif datatypes[t] == 'object':
            # make sure the target object of the zval is defined
            zobj = zval['value']['obj']
            if not self.get_objectptr(zobj):
                return False

        # shrug
        return True


    def visit_zval(self, zval):
        """
        Aggregates statistics given a single zval. Returns the total size of 
        the zval.
        """
        if self.accumulator.have_visited(zval.address):
            return 0

        z = Zval(zval)
        datatype = z.datatype()

        zs = zval_type.sizeof
        if datatype == 'object':
            size = self.visit_object_value(zval['value']['obj']) + zs
        elif datatype == 'string':
            string = zval['value']['str']
            strlen = int(zval['value']['str']['len'])
            try:
                if 'out of bounds' in str(string['val']):
                    size = zs
                else:
                    size = strlen + zs
            except:
                size = zs
        elif datatype in ('array', 'constant_array'):
            size = self.visit_hashtable(zval['value']['ht'].dereference()) + zs
        else:
            # the value types are stored within the zval. 
            size = zs

        self.accumulator.visited_zval(zval.address, datatype, size)
        return size


    def visit_hashtable(self, ht):
        """
        Walks a hash table, recording relevant statistics. Returns the size of
        the hash table and its contained objects. 
        """
        # the type contained within the hash table can be inferred from the 
        # destructor function pointer
        if self.accumulator.have_visited(ht.address):
            return 0

        dtor = ht['pDestructor']
        if 'zval_ptr_dtor' in str(dtor):
            return self.visit_zval_ptr_hash(ht)
        else:
            print 'unknown array, dtor:', dtor
        return -1000


    def visit_zval_ptr_hash(self, ht):
        # php arrays are implemented as chained hash tables: 
        #
        #  - The hash function (zend_inline_hash_func) maps a key to an index 
        #    in the arBuckets array. 
        #  - If multiple keys map to the same index, the buckets are chained
        #    using their pNext pointers. 
        #
        # Resizing, etc works like you would expect. 
        #
        # Furthermore, the buckets across the entire hash also form a linked 
        # list, from which spawns the php array hash/list duality (o_O). 

        # Notes about buckets:
        #  - The string key immediately follows the bucket in memory. 

        # The meaning of pData and pDataPtr appears to vary depending on what
        # is being stored in the bucket. The possibilities appear to be:
        #  - zval*
        #  - zend_module_entry
        #  - zend_function
        #  - null-termed file paths, other strings
        #  - zend_class_entry* 
        # 
        # TBD somewhat, but it seems as though for our purposes we can ignore 
        # all of these except for zval pointers since they pertain to codegen
        # and don't use the mm_heap. 
        
        s = hashtable_type.sizeof

        # account for the array of bucket chains
        nTableSize = int(ht['nTableSize'])
        bpsize = bucketptr_type.sizeof
        s += nTableSize * bpsize

        for b in hashtable_buckets(ht):
            s += bucket_type.sizeof - char_type.sizeof + b['nKeyLength']
            s += self.visit_zval(b.data_as_zval())
        
        return long(s)


    def get_objectptr(self, zobj):
        """
        Gets a zend_object* given a zend_object_value structure. (The struct 
        contains an object handle that has to be mapped to the real address.)
        """
        # The handle is used as a simple offset in a global object table, kept
        # in the executor_globals. The entry in the table has the pointer.
        handle = int(zobj['handle'])
        store = self.eg['objects_store']

        h = long(handle)
        if h < 0 or h > long(store['size']):
            return None

        buckets = store['object_buckets']
        bucket = (buckets + handle).dereference()['bucket']
        p = objptr(bucket['obj']['object'])
        return p


    def visit_object_value(self, zobj):
        # note that the size of zobj is accounted for in the enclosing 
        # zvalue_value.
        return self.visit_object_ptr(self.get_objectptr(zobj))


    def visit_object_ptr(self, zend_object_ptr):
        if self.accumulator.have_visited(zend_object_ptr):
            return 0

        s = self.size_zend_object_ptr(zend_object_ptr)

        z = ZendObject(zend_object_ptr.dereference())
        self.accumulator.visited_object(zend_object_ptr, z.class_name(), s)
        return s


    def size_zend_object_ptr(self, zend_object_ptr):
        zobj = zend_object_ptr.dereference()
        props = zobj['properties'].dereference()
        s = object_type.sizeof 

        if zobj['properties']:
            s += self.visit_hashtable(zobj['properties'].dereference())
        if zobj['guards']:
            s += self.visit_hashtable(zobj['guards'].dereference())
            
        return s





class HeapCrawler(object):
    def __init__(self, accumulator = None):
        self.accumulator = accumulator
        alloc_globals = gdb.selected_frame().read_var('alloc_globals')
        self.heap = alloc_globals['mm_heap'].dereference()


    def reset_stats(self):
        self.block_count = 0
        self.free_block_count = 0
        self.free_space = 0
        self.used_block_count = 0
        self.used_space = 0
        self.largest_free_block = 0


    def found_objects(self):
        return self.crawler.found_objects()


    def results(self):
        return self.crawler.accumulator


    def crawl(self):
        """
        Walks the entire heap, collecting stats. 
        """
        self.log('Analyzing heap ')

        self.reset_stats()
        self.crawler = Crawler(self.accumulator)

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

        size = self.count_block_size(blockptr)
        if size < 0:
            # free block
            return 

        data = zend_mm_data_of(blockptr)
        self.crawler.visit_voidptr(data, size)


    def count_block_size(self, blockptr):
        """
        Given a block, tracks its free or used space. Also keeps track of 
        some aggregated statistics. 

        Returns the count of bytes in the block, not counting the block header.
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
        return size


    def print_stats(self):
        block_overhead = self.block_count * block_type.sizeof
        print 'Real size:', human_size_bytes(self.heap['real_size'])
        print 'Peak size:', human_size_bytes(self.heap['real_peak'])
        print 'Memory limit:', human_size_bytes(self.heap['limit'])
        print
        print 'Block count:', self.block_count
        print 'Free blocks:', self.free_block_count
        print 'Free space:', human_size_bytes(self.free_space)
        print 'Largest free block:', human_size_bytes(self.largest_free_block)
        print 'Block header overhead:', human_size_bytes(block_overhead)
        print 'Used blocks:', self.used_block_count
        print 'Used space:', human_size_bytes(self.used_space)
        print
        self.results().print_zval_table()



class ObjectCrawler(object):
    def __init__(self, objects):
        self.objects = objects


    def crawl(self):
        self.crawler = Crawler()

        for p in self.objects:
            self.crawler.visit_object_ptr(p)


    def results(self):
        return self.crawler.accumulator


    def print_stats(self):
        eg = gdb.selected_frame().read_var('executor_globals')
        print 'Object store buckets:', eg['objects_store']['size']
        print
        self.results().print_object_table()



class PHPHeapDiag(gdb.Command):
    """
    Command that scans the entire heap and performs an analysis of usage. 
    
    Call with no arguments. 
      
      (gdb) php-heap-diag
    
    """
    def invoke(self, arg, from_tty):
        """
        Runs the command.
        """
        self.heap_crawler = HeapCrawler()
        self.heap_crawler.crawl()

        self.zval_results = self.heap_crawler.results()
        objects = self.heap_crawler.found_objects()

        self.object_crawler = ObjectCrawler(objects)
        self.object_crawler.crawl()

        self.heap_crawler.print_stats()
        self.object_crawler.print_stats()



class ListObjects(gdb.Command):
    """
    Dumps out a table listing the address of every object of a particular
    type, along with its size. 
    """
    def invoke(self, classname, from_tty):
        acc = ClassAccumulator(classname)
        c = HeapCrawler(acc)
        c.crawl()
        
        fmt = '%-30s %-10s'
        title = fmt % ('Address', 'Size')
        print title
        print '-'*len(title)

        xs = c.found_objects()
        sumsizes = 0
        for x in xs:
            s = acc.get_size(x)
            print fmt % (x, human_size_bytes(s))
            sumsizes += s

        print '-'*len(title)
        print fmt % ('%d instances' % len(xs), human_size_bytes(sumsizes))
        print



class DumpObject(gdb.Command):
    def invoke(self, address, from_tty):
        address = arg_to_address(address)
        z = ZendObject(objptr(voidptr(gdb.Value(address))).dereference())
        
        fmt = '%-3s %-30s %-10s  %s' 
        print 'Type:', z.class_name()
        print
        print fmt % ('', 'name', 'type', 'value')
        print '-'*80
        for i, n, b in zip(itertools.count(1),
                           z.field_names(), 
                           z.iterproperties()):
            z = Zval(b.data_as_zval())
            print fmt % (i, n, z.datatype(), z.get_value())



group = gdb.COMMAND_DATA
PHPHeapDiag('php-heap-diag', group)
ListObjects('list-objects', group)
DumpObject('dump-object', group)
