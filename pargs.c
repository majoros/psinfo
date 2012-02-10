#include <link.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <libelf.h>

#define MAX_STR_LEN 4096;

#define LOG_DEBUG  0
#define LOG_INFO   1
#define LOG_ERROR  2
#define MAX_MSG    256
/*
 * search locations of DT_SYMTAB and DT_STRTAB and save them into global
 * variables, also save the nchains from hash table.
 */

/*
 * Research:
 *    http://www.acsu.buffalo.edu/~charngda/elf.html
 *    http://www.ibm.com/developerworks/linux/library/l-dynamic-libraries/
 *    http://www.symantec.com/connect/articles/dynamic-linking-linux-and-windows-part-one
 *
 */

void logit( int msg_level, const char *fmt, ... );

int log_level = LOG_ERROR;
int aflag = 1;
int cflag = 0;
int eflag = 0;
int lflag = 0;
int xflag = 0;
int Fflag = 0;
int dflag = 0;

int env;
int _env;
int __env;

unsigned long symtab;
unsigned long strtab;

int nchains = 0;

/* attach to pid */
void ptrace_attach(int pid) {
    if((ptrace(PTRACE_ATTACH, pid, NULL, NULL)) < 0) {
        logit( LOG_ERROR, "ERROR: Unable to attach to [%i]: %i\n", pid, errno );
        exit(-1);
    }
    waitpid(pid, NULL, WUNTRACED);
}

/* detach process */
void ptrace_detach(int pid) {
    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        logit( LOG_ERROR, "ERROR: Unable to detach from [%i]: %i\n", pid, errno );
        exit(-1);
    }
}

/* read data from attached process's memory address */
void read_data(int pid, unsigned long addr, void *vptr, int len){
    /* TODO: Check if we are going to go out on bounds and then do... somthing */
    int i, count;
    long word;
    unsigned long *ptr = (unsigned long *) vptr;
    count = i = 0;
    while (count < len) {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
        count += sizeof(int);
        ptr[i++] = word;
    }
}

/* read string from pid's memory */
char *read_str(int pid, unsigned long addr, int max) {
    int i, count;
    long word;
    char *str = calloc(max, sizeof(char));
    count = i = 0;
    while (count < max) {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
        count += sizeof(char);
        str[i++] = word;
        if( (char)word == '\0'){
            goto END;
        }
    }

END:
    return (char *) str;
}

/* locate link-map in pid's memory */
struct link_map *locate_linkmap(int pid) {

    Elf32_Ehdr *ehdr = malloc(sizeof(Elf32_Ehdr));
    Elf32_Phdr *phdr = malloc(sizeof(Elf32_Phdr));
    Elf32_Dyn  *dyn  = malloc(sizeof(Elf32_Dyn));
    Elf32_Word got;

    struct link_map *l = malloc(sizeof(struct link_map));
    unsigned long phdr_addr, dyn_addr, map_addr;

    /*
     * First we check from elf header, mapped at 0x08048000, the offset
     * to the program header table from where we try to locate
     * PT_DYNAMIC section.
     *
     * TODO: Don't guess the 0x08048000 address
     */

    read_data(pid, 0x08048000, ehdr, sizeof(Elf32_Ehdr));
    phdr_addr = 0x08048000 + ehdr->e_phoff;


    /*
     * Just making sure we have the actual elf header
     */
    if( (int)ehdr->e_ident[0] != 0x7f ||
        (int)ehdr->e_ident[1] != 'E'  ||
        (int)ehdr->e_ident[2] != 'L'  ||
        (int)ehdr->e_ident[3] != 'F' ){
        logit( LOG_ERROR, "Can't find a proper elf header\n");
        return;
    }

    logit( LOG_DEBUG, "DEBUG: Program header at %p %c\n",(void *) phdr_addr, ehdr->e_ident[1]);

    read_data(pid, phdr_addr, phdr, sizeof(Elf32_Phdr));

    /*
     * now go through dynamic section until we find address of the GOT
     */
    while (phdr->p_type != PT_DYNAMIC) {
        read_data(pid, phdr_addr += sizeof(Elf32_Phdr), phdr,
              sizeof(Elf32_Phdr));
    }

    read_data(pid, phdr->p_vaddr, dyn, sizeof(Elf32_Dyn));
    dyn_addr = phdr->p_vaddr;

    while (dyn->d_tag != DT_PLTGOT) {
        read_data(pid, dyn_addr +=
              sizeof(Elf32_Dyn), dyn, sizeof(Elf32_Dyn));
    }

    /*
     * TODO: Need to find a way to make sure what i'm getting is the actual GOT
     * and that I have not been going through some random memory addresses
     * getting who knows what.
     */

    got = (Elf32_Word) dyn->d_un.d_ptr;
    got += sizeof(int);  /*  second GOT entry */
    logit( LOG_DEBUG, "DEBUG: The GOT address is %p\n", got);
    /* we got the GOT! */

    /*
     * Read first link_map item and return it
     */
    read_data(pid, (unsigned long) got, &map_addr, sizeof(int));
    read_data(pid, map_addr, l, sizeof(struct link_map));
    /* again how do i know i am getting what i want. */

    free(phdr);
    free(ehdr);
    free(dyn);
    return l;
}

/* resolve the tables for symbols*/
void resolv_tables(int pid, struct link_map *map) {

    Elf32_Dyn *dyn = malloc(sizeof(Elf32_Dyn));

    unsigned long addr;

    addr = (unsigned long) map->l_ld;

    read_data(pid, addr, dyn, sizeof(Elf32_Dyn));

    while (dyn->d_tag) {
        switch (dyn->d_tag) {
        case DT_HASH:
            read_data(pid, dyn->d_un.d_ptr +
                  map->l_addr + 4, &nchains,
                  sizeof(nchains));
            break;
        case DT_STRTAB:
            logit( LOG_DEBUG, "DEBUG: strtab address: %i\n", dyn->d_tag);
            strtab = dyn->d_un.d_ptr;
            break;
        case DT_SYMTAB:
            logit( LOG_DEBUG, "DEBUG: symtab address: %i\n", dyn->d_tag);
            symtab = dyn->d_un.d_ptr;
            break;
        default:
            break;
        }
        addr += sizeof(Elf32_Dyn);
        read_data(pid, addr, dyn, sizeof(Elf32_Dyn));
    }
    free(dyn);
}

/* find symbol in DT_SYMTAB */
void find_environ_sym(int pid, struct link_map *map) {
    Elf32_Sym *sym = malloc(sizeof(Elf32_Sym));
    char *str;
    int val;
    int i = 0;

    do{
        read_data(pid, symtab + (i * sizeof(Elf32_Sym)), sym,
              sizeof(Elf32_Sym));
        i++;

        str = read_str(pid, strtab + sym->st_name, 64);
        /* compare it with our symbol
        printf("size: %i str: %s  %i\n", sym->st_info, str, i);
        */

        if (strcmp(str, "environ") == 0) {
            env = (map->l_addr + sym->st_value);
            logit( LOG_DEBUG, "DEBUG: environ symbol address: %p\n", env);
        }
        else if (strcmp(str, "_environ") == 0) {
            _env = (map->l_addr + sym->st_value);
            logit( LOG_DEBUG, "DEBUG: _environ symbol address: %p\n", _env);
        }
        else if (strcmp(str, "__environ") == 0) {
            __env = (map->l_addr + sym->st_value);
            logit( LOG_DEBUG, "DEBUG: __environ symbol address: %p\n", __env);
        }

    }while( (int)str[0] != -1 ); /* FIXME: */

    return;

}

void show_environ( int pid ){

    char *str;
    int sym_addr;
    int env_addr;
    int str_addr;
    int f = 0;

    /* TODO: hhhmmm how many of these can there be? */
    if( (int*)__env != NULL ){
        sym_addr = __env;
    }

    if( (int*)_env != NULL ){
        sym_addr = _env;
    }

    if( (int*)env != NULL ){
        sym_addr = env;
    }

    if( (int*)sym_addr == NULL ){
        logit( LOG_ERROR, "ERROR: Unable to find an environ symbol\n");
        return;
    }
    logit( LOG_DEBUG, "DEBUG: The environ symbol address: %p\n", sym_addr );

    /* we only have the address to the symbol of environ. Now we want
     * the actual environ pointer
     */
    read_data(pid, sym_addr, &env_addr, sizeof(int));

    logit( LOG_DEBUG, "DEBUG: The environ array address: %p\n", env_addr);

    /*
     * now we can FINALLY loop through the array of environment
     * variables. Get the first one and then loop until nil
     */
    read_data(pid, env_addr, &str_addr, sizeof(int));

    int i = 0;
    do{
        i++;
        str = read_str(pid, str_addr, 4096 );
        printf( "%s\n", str);

        env_addr += sizeof(int);
        read_data(pid, env_addr, &str_addr, sizeof(int));
    } while( str_addr != 0 ); /* TODO: zero ??? */
}

void usage() {
}

void display_args() {
}

void display_env( int pid ){
    int ret;
    struct link_map *lm;

    ptrace_attach(pid);

    lm = locate_linkmap(pid);

    resolv_tables(pid, lm);

    find_environ_sym(pid, lm);

    show_environ(pid);

    ptrace_detach(pid);
}

int main(int argc, char **argv) {

    int c;
    int pid;

    opterr = 0;

    while (( c = getopt( argc, argv, "acelxvF:" )) != -1 )
        switch (c)
        {
            case 'a':
                aflag = 1;
                break;
            case 'c':
                cflag = 1;
                break;
            case 'e':
                eflag = 1;
                break;
            case 'l':
                lflag = 1;
                break;
            case 'x':
                xflag = 1;
                break;
            case 'F':
                Fflag = 1;
                break;
            case 'd':
                dflag = 1;
                break;
            case 'v':
                log_level--;
                printf("log level %i\n", log_level);
                break;
            default:
                usage();
        }

    if( argc == optind ){
        logit( LOG_ERROR, "You must supply a single pid\n" );
        exit(1);
    }

    pid = atoi( argv[optind] );

    if( aflag )
        display_args(pid);

    if( eflag )
        display_env(pid);
}

void logit( int msg_level, const char *fmt, ... ){

    va_list ap;
    char msg[MAX_MSG];

    if( msg_level >= log_level ){
        va_start(ap, fmt);
        vfprintf( stderr, fmt, ap );
        va_end(ap);
    }
}

