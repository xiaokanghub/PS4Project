#include <stdio.h>
int main(int argc, char *argv[])
{
    // int i = 0;
    // // go through each string in argv
    // // why am I skipping argv[0]?
    // for(i = 1; i < argc; i++) {
    //     printf("arg %d: %s\n", i, argv[i]);
    // }
    // let's make our own array of strings
    char *states[] = {
        "proc","execlabel","vp","object","attr","image_header","entry_addr","reloc_base","vmspace_destroyed","interpreted","opened","interpreter_name","auxargs","firstpage","ps_strings","auxarg_size","args","sysent","execpath","execpathp","freepath","canary","canarylen","pagesizes","pagesizeslen","stack_prot"
    };
    int num_states = 26;
    for(int i = 0; i < num_states; i++) {
        printf("state %d: %s\n", i, states[i]);
    }
    return 0;
}