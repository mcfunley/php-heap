Overview
========

This is a gdb extension that can be used for examining the objects in memory in a running PHP process or core dump. It walks the low-level PHP memory structures to do this and should work without code modifications. 

By Dan McKinley, 2010
[http://mcfunley.com](http://mcfunley.com)


Requirements
============

This package was tested with PHP 5.2.X on CentOS 5.3. 

In order to use this extension, you need:

* PHP compiled with debug symbols. 
* GDB version 7 or later. 

Please note that you merely need debug symbols for PHP, you do not want to compile it with `--enable-debug`. (`--enable-debug` is a different animal, it enables sanity checks that are internal to PHP. It will actually skew the output significantly, because it adds overhead to each heap block.)

When you attach with gdb you should see:

`Reading symbols from /usr/bin/php...done.`

Instead of:

`(no debugging symbols found)`


Usage
=====

After attaching to a process or starting a process run, you can include php-heap using the `source` command:

    (gdb) source php-heap.py

(There are ways to have gdb automatically load the extension, see the gdb documentation.)

After you have done this there are a number of commands at your disposal:

* `php-heap-diag` - Walks the entire heap and prints a table of summary information.
* `list-objects <classname>` - Prints out the addresses of all instances of a particular class.
* `dump-object <address>` - Displays information about an object instance, given its address.
* `dump-array <address>` - Displays the keys and values of a PHP array, given its address.


Disclaimers
===========

Dumping out the PHP heap involves a certain amount of guesswork. When it is compiled with the standard flags there is not generally enough reflection information on the heap to tell what everything is for certain, especially primitives. So this extension takes a "if it looks like a zval it probably is a zval" approach, with the assumption that any errors will not matter statistically. 

There also seem to be some uses of the heap that it does (yet) not handle at all. 


TODOs
=====
* Dumping out memory by first walking down the stack may produce more reliable results. And it would also be useful to have a frame-by-frame dump of the references held. 
* Need to figure out remaining uses of the heap that are not covered at all. 