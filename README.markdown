PSINFO
======

Intro
-----

This program extracts information about a process from within the processes
memory. It retrieves information that is either difficult or impossible to
retrieve. Yes you can use GDB to get all this information (but thats no fun).


Types of Information
--------------------

Environment Variables

Up until recently I thought that the information in /proc/$$/environ was the
current environment for that process. However it is actually the environment of
the process at execution time. The environment is inishally stored in the
processes stack. If the process modifies its environment Linux maloc's new
space and copies the environment to the heap and updates the environ symbol to
point to the new location.

One of the functions that gets run when a process starts is the
create_elf_tables[1] function. This function creates and populates a
mm_struct[2]. This structure, among other things, contains env_start and
env_end, which are the memory address of the beggining and end of the
environment variable data. The proc file system reads this information from the
mm_struct when the environ_read[3] function is called. So the proc file system
is giving you the environment at execution time and not the current
environment. Also the gdb command "who environ" also gives you the environment
at execution time (I am assuming its doing the same thing but i have not looked
into it yet). You can get the address of the environ symbol from gdb and
get the data that way.

  [1] https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c
  [2] https://github.com/torvalds/linux/blob/master/include/linux/mm_types.h
  [3] https://github.com/torvalds/linux/blob/master/fs/proc/base.c

