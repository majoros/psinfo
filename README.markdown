Up until recently I thought that the information in /proc/$$/environ was the
current environment for that process. However it is actually the environment of
the process at execution time. The environment is initially stored in the
processes stack. If the process modifies its environment Linux maloc's new
space and copies the environment to the heap and updates the environ symbol to
point to the new location.

One of the functions that gets run when a process starts is the
[create_elf_tables][] function. This function creates and populates a
[mm_struct][]. This structure, among other things, contains env_start and
env_end, which are the memory address of the beggining and end of the
environment variable data. The proc file system reads this information from the
mm_struct when the [environ_read][] function is called. So the proc file system
is giving you the environment at execution time and not the current
environment. Also the gdb command "who environ" also gives you the environment
at execution time (I am assuming its doing the same thing but i have not looked
into it yet). You can get the address of the environ symbol from gdb and
get the data that way.

[create_elf_tables]: https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c
[mm_struct]: https://github.com/torvalds/linux/blob/master/include/linux/mm_types.h
[environ_read]: https://github.com/torvalds/linux/blob/master/fs/proc/base.c


