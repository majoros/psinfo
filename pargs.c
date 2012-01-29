#include <link.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <ctype.h>
#include <unistd>
#include <stdio.h>
#include <errno.h>

#define ENVIRON environ;

/* 
 * search locations of DT_SYMTAB and DT_STRTAB and save them into global
 * variables, also save the nchains from hash table.
 */

/*
 * Research:
 *    http://www.acsu.buffalo.edu/~charngda/elf.html
 *    http://www.ibm.com/developerworks/linux/library/l-dynamic-libraries/
 *
 */

unsigned long symtab;
unsigned long strtab;
int nchains;

/* attach to pid */
void ptrace_attach(int pid) {
    if((ptrace(PTRACE_ATTACH, pid, NULL, NULL)) < 0) {
        perror("ptrace_attach");
        exit(-1);
    }
    waitpid(pid, NULL, WUNTRACED);
}

/* detach process */
void ptrace_detach(int pid) {
    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        perror("ptrace_detach");
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
        count += 4;
        ptr[i++] = word;
    }
}
/* read string from pid's memory */
char *read_str(int pid, unsigned long addr, int len)
{
    char *ret = calloc(32, sizeof(char));
    read_data(pid, addr, ret, len);
    return ret;
}

/* locate link-map in pid's memory */
struct link_map *locate_linkmap(int pid) {
    Elf32_Ehdr *ehdr = malloc(sizeof(Elf32_Ehdr));
    Elf32_Phdr *phdr = malloc(sizeof(Elf32_Phdr));
    Elf32_Dyn *dyn = malloc(sizeof(Elf32_Dyn));
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

    /* printf("program header at %p\n",(void *) phdr_addr); */

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
     * TODO: Need to find a way to make sure what im getting is the actual GOT
     * and that i have not been going through some random memory addresses
     * getting who knows what.
     */

    got = (Elf32_Word) dyn->d_un.d_ptr;
    got += 4;   /* second GOT entry */

    /*
     * Read first link_map item and return it
     */
    read_data(pid, (unsigned long) got, &map_addr, 4);
    read_data(pid, map_addr, l, sizeof(struct link_map));
    /* again how do i know i am getting what i want. */

    free(phdr);
    free(ehdr);
    free(dyn);
    return l;
}

/* resolve the tables for symbols*/
void resolv_tables(int pid, struct link_map *map)
{
    Elf32_Dyn *dyn = malloc(sizeof(Elf32_Dyn));
    unsigned long addr;
    addr = (unsigned long) map->l_ld;
    read_data(pid, addr, dyn, sizeof(Elf32_Dyn));
    while (dyn->d_tag) {
        switch (dyn->d_tag) {
        case DT_HASH:
            read_data( pid,
                       dyn->d_un.d_ptr + map->l_addr + 4,
                       &nchains,
                       sizeof(nchains)
                     );
            break;
        case DT_STRTAB:
            strtab = dyn->d_un.d_ptr;
            break;
        case DT_SYMTAB:
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
int find_sym_in_tables(int pid, struct link_map *map)
{
    Elf32_Sym *sym = malloc(sizeof(Elf32_Sym));
    char *str;
    int env;
    int val;
    int i = 0;
    int f = 0;

    while (i < nchains) {
        read_data(pid, symtab + (i * sizeof(Elf32_Sym)), sym,
              sizeof(Elf32_Sym));
        i++;

        str = read_str(pid, strtab + sym->st_name, 8);
        /* compare it with our symbol*/
        if (strcmp(str, "environ") == 0) {
            f = 1;

            /* we have the address to the symbol of environ. now we want what
             * the actual environ pointer
             */
            read_data(pid, ( map->l_addr + sym->st_value), &env, 4);

            /*
             * now we can FINALLY loop through the aray of environment
             * variables. Get the first one and then loop untill nil
             */

            read_data(pid, env, &val, 4);
            while( val != 0 ){
                str = read_str(pid, val, 32);
                printf( "%s\n", str);
                env += 4;
                read_data(pid, env, &val, 4);
            }
        }
    }
    return f;
}

int main(int argc, char *argv[])
{

    int c;

    int aflag = 1;
    int cflag = 0;
    int eflag = 0;
    int lflag = 0;
    int xflag = 0;
    int Fflag = 0;

    int pid;
    int ret;
    unsigned long *value;
    struct link_map *lm;

    while (( c = getopt( argc, argc, "acelxF:" )) != -1 ){
        switch (c){
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
        }
    }

    if( argc != 1 ){
        fprintf( stderr, "You must supply a single pid\n");
        exit 1;
    }

    pid = atoi(argv[1]);
    ptrace_attach(pid);

    lm = locate_linkmap(pid);
    resolv_tables(pid, lm);

    ret = find_sym_in_tables(pid, lm);

    ptrace_detach(pid);
    return 0;
}

