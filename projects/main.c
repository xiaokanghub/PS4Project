#define _XOPEN_SOURCE 700
#define __BSD_VISIBLE 1
#define _KERNEL
#define _STANDALONE
#define _WANT_UCRED
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/limits.h>
#include <sys/param.h>
#include <sys/kernel.h>
//#include <sys/libkern.h>
#include <sys/systm.h>

#include <sys/sysproto.h>
//#include <sys/unistd.h>
#include <sys/syscallsubr.h>

#include <ps4/kernel.h>

#define SERVER_PORT 5088

Ps4KernelSocket *patch_another_sock;

#include <stddef.h>
#include <sys/proc.h>
#include <sys/kthread.h>

#include <imgact.h>

uint64_t (*r_sys_dynlib_dlsym)(uint64_t rdi, uint64_t rsi);
uint64_t (*r_sys_mprotect)(uint64_t rdi, uint64_t rsi);
uint64_t (*r_sys_open)(uint64_t rdi, uint64_t rsi);

int probe() {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    ps4KernelSocketPrint(td, patch_another_sock, "probe \n");

    pause("paused", 10000);

    ps4KernelSocketPrint(td, patch_another_sock, "unpaused\n");
}

char dump[0x1000];

#include <pmap.h>

#include <machine/pmap.h>
#include <vm/vm.h>
#include <vm/vm_map.h>

int write_mem(struct thread *td, struct proc *p, uint64_t base, char *buff, int size) {
    struct uio uio;
    struct iovec iov;
    iov.iov_base = (void*)buff;
    iov.iov_len = size;

    uio.uio_iov = &iov;
    uio.uio_iovcnt = 1;
    uio.uio_offset = base;
    uio.uio_resid = size;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_rw = UIO_WRITE;
    uio.uio_td = td;

    int ret = proc_rwmem(p, &uio);
    return ret;
}


char * msearch(char * start, char * haystack, int size) 
{
    char* mymem = start;
    for(;;){
        if (strncmp(mymem, haystack, size) == 0){
            return mymem;
        }
        mymem ++;
    }
}

char dump2[0x4000];
void socketprintsection(struct thread *td, char * title, uint64_t pos, uint64_t size)
{
        ps4KernelSocketPrint(td, patch_another_sock, title);
        bzero(dump2, size);
        copyin(pos, dump2, size);
        ps4KernelSocketPrintHexDump(td, patch_another_sock, dump2, size);
        ps4KernelSocketPrint(td, patch_another_sock, "\n");
}

uint64_t kern_load_elf(struct image_params *imgp, char * filename, uint64_t * outprocentry);

void add_0x93a4FFFF8_gadget(struct thread *td, struct image_params *imgp, uint64_t kernel_start) {
    struct vmspace *vmspace;
    vm_map_t map;

    vmspace = imgp->proc->p_vmspace;
    map = &vmspace->vm_map;

    //insert hito gadget
    uint64_t gadget = kernel_start + (0x45a - 0x1bd58);//1.76 specific, kernel syscall/ret gadget, - kernel.start

    int error = vm_map_insert(map, NULL, 0,
        0x93a4fc000, 0x93a500000,
        VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL, 0);

    copyout(&gadget, 0x93a4FFFF8, 8); 

    
    socketprintsection(td, "hito gadget2:\n", 0x93a4FFFF8, 8);
    socketprintsection(td, "gadget content:\n", gadget, 0x10);
}

void entry_point_replace(struct thread *td, struct image_params *imgp, uint64_t stack_base, uint64_t new_entry)
{
            ps4KernelSocketPrint(td, patch_another_sock, "new program entrypoint: %llx\n", new_entry);

            
            //ps4KernelSocketPrint(td, patch_another_sock, "setting regs\n", imgp->args->fname);

            bzero(dump, 0xc0*2);
            copyin(stack_base, dump, 0xc0*2);

            socketprintsection(td, "stack_base dump:\n", stack_base, 0xc0);


            //gotta find where this is writen to get a better definition
            uint64_t * p_program_entry = (uint64_t*)(dump + 0x70 + (imgp->args->argc * 8) + (imgp->args->envc * 8));
            uint64_t program_entry = * p_program_entry;

            ps4KernelSocketPrint(td, patch_another_sock, "program bss: %llx\n", p_program_entry[2] & 0x7ffffffff);

            socketprintsection(td, "module bss?:\n", (p_program_entry[2] & 0x7ffffffff) + 0x2c0, 0x100);

    //overwrite the program entry
            * p_program_entry = new_entry;
            copyout(dump, stack_base, 0xc0*2); 

            socketprintsection(td, "stack_base dump:\n", stack_base, 0xc0);

            socketprintsection(td, "program entry:\n", new_entry, 0x200);

            uint64_t kernel_entry = imgp->entry_addr;
            add_0x93a4FFFF8_gadget(td, imgp, kernel_entry);

            copyout(&program_entry, 0x93a4FFFF0, 8); 
}

//exec_setregs(td, imgp, (u_long)(uintptr_t)stack_base);
uint64_t hook_exec_set_regs(struct thread *td, struct image_params *imgp, uint64_t stack_base) {
    uint64_t (*f)(uint64_t td, struct image_params *imgp, uint64_t stack_base) = 0xffffffff82603ce0;

    ps4KernelSocketPrint(td, patch_another_sock, "setting regs for %s rip(should be libkernel->start): %llx \n", imgp->args->fname, imgp->entry_addr);

    uint64_t kernel_start = imgp->entry_addr;

    int ret = f(td, imgp, stack_base);

    socketprintsection(td, "kernel entry\n", imgp->entry_addr, 0x20);
    ps4KernelSocketPrint(td, patch_another_sock, "stack_base %llx:\n", stack_base);

    char * found_hihack_command = NULL;
    const char * magic = "!_MAGIC_RUN_THIS_!";
    int slen = strlen(magic);
    for(char* mymem = imgp->args->buf ;(imgp->args->endp - mymem) >= 8; mymem ++){
        if (strncmp(mymem, magic, slen) == 0) {
            found_hihack_command = mymem + slen;
            break;
        }
    }

    ps4KernelSocketPrint(td, patch_another_sock, "found? %d\n", found_hihack_command);
    if (found_hihack_command)
        ps4KernelSocketPrint(td, patch_another_sock, "new program: %s\n", found_hihack_command);

    //socketprintsection(td, "mapped file\n", 0x900000, 0x60);

    if ((found_hihack_command != NULL) & (imgp->args->fname != NULL) & (strstr(imgp->args->fname,"WebProcess.self") > 0))
    {

        ps4KernelSocketPrint(td, patch_another_sock, "stack_base %llx:\n", stack_base);

        ps4KernelSocketPrint(td, patch_another_sock, "HIHACKING PROC\n");

        uint64_t new_entry = 0;

        int error = kern_load_elf(imgp, found_hihack_command, &new_entry);
        if (error == 0)
        {
            entry_point_replace(td, imgp, stack_base, new_entry);
        }

    }

    if ((imgp->args->fname != NULL) & 
            ((strstr(imgp->args->fname,"CUSA") > 0) | (strstr(imgp->args->fname,"eboot") > 0)))
    {
        ps4KernelSocketPrint(td, patch_another_sock, "Loading custom module\n");

        //where mmap(0...) would put it
        uint64_t new_entry = 0; //new_entry = imgp->proc->p_vmspace->vm_daddr;

        int error = kern_load_elf(imgp, "/app0/eboot_plugin", &new_entry);
        if (error == 0)
        {
            entry_point_replace(td, imgp, stack_base, new_entry);
        }
    }


    return ret;
}

int doloadelf(struct thread *td, char * imgname, uint64_t destaddr) {
    struct image_params imgp;
    uint64_t new_entry = 0;

    copyin(destaddr, &new_entry, 8);
    
    char buf[400];

    copyin(imgname, buf, 400);

    imgp.proc = td->td_proc;

    int error = kern_load_elf(&imgp, buf, &new_entry);

    copyout(&new_entry, destaddr, 8);

    return error;
}

// ex kldstat
// offset, fd, prot, 
uint64_t custom_sycall_gate(uint64_t rdi, uint64_t rsi)
{
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    uint64_t arg0 = *(uint64_t*)(rsi + 0);
    uint64_t arg1 = *(uint64_t*)(rsi + 8);
    uint64_t arg2 = *(uint64_t*)(rsi + 16);
    uint64_t arg3 = *(uint64_t*)(rsi + 24);

    char buf[400];

    switch (arg0)
    {
        case 0x0:
            //ps4KernelSocketPrint(td, patch_another_sock, "gate_syscall :: writemem (%llx, %llx, %llx)\n", arg1, arg2, arg3);
            //writemem(source, dest, size)
            {
            struct malloc_type *mt = ps4KernelDlSym("M_TEMP");

            //struct proc *p = pfind(args->pid);

            void *buff = malloc(arg3, mt, M_ZERO | M_WAITOK);
            copyin(arg1, buff, arg3);
            int ret = write_mem(td, td->td_proc, arg2, buff, arg3);
            free(buff, mt);
            }

            break;
        case 0x1:
            //mprotect?
            break;
        case 0x2:
            copyin(arg1, buf, 400);
            ps4KernelSocketPrint(td, patch_another_sock, "%s", 
                buf);
            //log?
            break;

        case 0x3:
            return doloadelf(td, arg1, arg2);

        default:
            ps4KernelSocketPrint(td, patch_another_sock, "gate_syscall :: unknown (%llx, %llx, %llx, %llx, %llx, %llx)\n", 
                *(uint64_t*)(rsi + 0), 
                *(uint64_t*)(rsi + 8), 
                *(uint64_t*)(rsi + 16), 
                *(uint64_t*)(rsi + 24), 
                *(uint64_t*)(rsi + 32), 
                *(uint64_t*)(rsi + 40));

            return 1;
    }
    // error = vm_map_insert(map, object, 
    //     0, //file_offset
    //     0x400000, 0x400200, //virtual_offset, text_end,
    //     VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_ALL, 
    //     MAP_COPY_ON_WRITE | MAP_PREFAULT);

    return 0;
}


uint64_t sycall_hook_open(uint64_t rdi, uint64_t rsi)
{

    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    ps4KernelSocketPrint(td, patch_another_sock, "r_sys_open v1 (%llx, %s, %llx)\n", 
        *(uint64_t*)(rsi + 0), *(uint64_t*)(rsi + 8), *(uint64_t*)(rsi + 16));

    uint64_t error = r_sys_open(rdi, rsi);

    return error;
}

uint64_t sycall_hook_dlsymbol_resolv(uint64_t rdi, uint64_t rsi)
{


    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    ps4KernelSocketPrint(td, patch_another_sock, "r_sys_dynlib_dlsym v1 (%llx, %s, %llx)\n", 
        *(uint64_t*)(rsi + 0), *(uint64_t*)(rsi + 8), *(uint64_t*)(rsi + 16));

    uint64_t error = r_sys_dynlib_dlsym(rdi, rsi);

    ps4KernelSocketPrint(td, patch_another_sock, "r_sys_dynlib_dlsym returned: %d\n", error);

    return error;

}

uint64_t hook_sys_mprotect(uint64_t rdi, uint64_t rsi)
{
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    ps4KernelSocketPrint(td, patch_another_sock, "sys_mprotect v1 (%llx, %llx, %llx)\n", 
        *(uint64_t*)(rsi + 0), *(uint64_t*)(rsi + 8), *(uint64_t*)(rsi + 16));

    uint64_t error = r_sys_mprotect(rdi, rsi);

    ps4KernelSocketPrint(td, patch_another_sock, "sys_mprotect returned: %d\n", error);

    return error;
}

uint64_t hook_sys_dynlib_load_prx(uint64_t rdi, uint64_t rsi)
{
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    uint64_t (*sys_dynlib_load_prx)(uint64_t rdi, uint64_t rsi) = 0xffffffff825e28f0;

    char name[0x400];
    copyin(*(uint64_t*)rsi, name, 0x400);


    int error = sys_dynlib_load_prx(rdi, rsi);
        ps4KernelSocketPrint(td, patch_another_sock, "sys_dynlib_load_prx loading lib %s\n", name);
    if (error != 0)
    {
        ps4KernelSocketPrint(td, patch_another_sock, "ERROR: sys_dynlib_load_prx ret: %d\n", error);
    }

    return error;
}

//might be disruptive, can be turned off
int printf_hook(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r1, uint64_t r2) {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    ps4KernelSocketPrint(td, patch_another_sock, "print hook, %s\n", rdi);
    ps4KernelSocketPrint(td, patch_another_sock, rdi, rsi, rdx, rcx, r1, r2);
}


int panic_hook(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx) {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    ps4KernelSocketPrint(td, patch_another_sock, "panic\n");
    ps4KernelSocketPrint(td, patch_another_sock, rdi, rsi, rdx, rcx);

    pause("hooked", 15000);
}

int myhook1(struct thread *td, Ps4KernelFunctionHookArgument *arg) {
    arg->returns->rax = 1;
    return PS4_KERNEL_FUNCTION_HOOK_CONTROL_CONTINUE;
}

int myhook2(struct thread *td, Ps4KernelFunctionHookArgument *arg) {
    arg->returns->rax = 0;
    return PS4_KERNEL_FUNCTION_HOOK_CONTROL_CONTINUE;
}

int path_self_mmap_check_function(struct thread *td, void *uap) {
    void *func1 = ps4KernelDlSym("sceSblACMgrIsAllowedToMmapSelf");
    void *func2 = ps4KernelDlSym("sceSblAuthMgrIsLoadable");
    ps4KernelFunctionPosthook(func1, myhook1);
    ps4KernelFunctionPosthook(func2, myhook2);
    return 0;
}

int unpath_self_mmap_check_function(struct thread *td, void *uap) {
    void *func1 = ps4KernelDlSym("sceSblACMgrIsAllowedToMmapSelf");
    void *func2 = ps4KernelDlSym("sceSblAuthMgrIsLoadable");
    ps4KernelFunctionUnhook(func1);
    ps4KernelFunctionUnhook(func2);
    return 0;
}

int exec_shell_imgact_patch();

int hook_self_imgact(struct image_params *imgp);

uint64_t solveprint_symbol(struct thread *td, struct socket * sock, char * name) {
    uint64_t exec_shell_imgact = ps4KernelDlSym(name);
    ps4KernelSocketPrint(td, sock, "%s => %llX\n", name, exec_shell_imgact);
    return exec_shell_imgact;
}

int flag = 0;

void nop_fill(start, count) {
    for (int i=0; i < count; i++)
    {
        *(uint8_t*)(start + i) = 0x90;
    }
}

void zero_eax(start) {
    *(uint8_t*)(start) = 0x48;
    *(uint8_t*)(start+1) = 0x31;
    *(uint8_t*)(start+2) = 0xc0;
}

void jmp_bridge(uint64_t start, uint64_t jmpdest) {
    *(uint8_t*)(start) = 0xff;
    *(uint8_t*)(start+1) = 0x25;
    *(uint8_t*)(start+2) = 0x00;
    *(uint8_t*)(start+3) = 0x00;
    *(uint8_t*)(start+4) = 0x00;
    *(uint8_t*)(start+5) = 0x00;
    *(uint64_t*)(start+6) = jmpdest;
}

uint64_t sceSblAuthMgrIsLoadable(uint64_t, uint64_t,uint64_t,uint64_t);

uint64_t sceSbleAuthMgrIsLoadeable_hook(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx)
{
    uint64_t * cur_stack;

    __asm__(
    "mov %%rbp, %0" 
        : "=r" (cur_stack) :
    );

    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    ps4KernelSocketPrint(td, patch_another_sock, "calling sceSblAuthMgrIsLoadable\n");

    //rcx = &imgp->isLoadeableData_136
    uint64_t error = sceSblAuthMgrIsLoadable(rdi, rsi, rdx, rcx);

    ps4KernelSocketPrint(td, patch_another_sock, "returned: %llx\n", error);

    return error;
}

uint64_t hook_sys_execve(uint64_t a1, uint64_t a2)
{
    uint64_t args[8];

    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    ps4KernelSocketPrint(td, patch_another_sock, "======================================\n");
    ps4KernelSocketPrint(td, patch_another_sock, "hook execve called\n");

    uint64_t result = exec_copyin_args(&args, *(uint64_t*)a2, 0, *(uint64_t*)(a2 + 8), *(uint64_t*)(a2 + 16));

    if (!result)
    {
        socketprintsection(td, "executing prog: \n", args[4], 0x20);
        if (strstr(args[4], "eboot.bin") != 0)
        {
            strcpy(args[4], "/app0/eboot_dec.bin"); //00265.bin
        }
        result = kern_execve(a1, &args, 0);
        ps4KernelSocketPrint(td, patch_another_sock, "execve: going back to usermode\n");
    }
    return result;
}

uint64_t hook_sys_mount(uint64_t a1, uint64_t * a2) {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    ps4KernelSocketPrint(td, patch_another_sock, "sys_mount %s %s %s\n", a2[0], a2[1], a2[2]);
    return sys_mount(a1, a2);
}



uint64_t getoffset(struct thread *td, struct socket * sock){ struct  internal_state  imgp;
	 unsigned *states[] = {" dummy"};
     int num_states = sizeof(*states);
     ps4KernelSocketPrint(td, sock,"%d\n",num_states);
     for(int i = 0; i < num_states; i++) {
         ps4KernelSocketPrint(td, sock,"%d\n",states[i]-(unsigned)&kby);
     }
     return 0;

 }

uint64_t hook_sys_nmount(uint64_t a1, uint64_t * a2) {
    struct thread *td;
    ps4KernelThreadGetCurrent(&td);

    ps4KernelSocketPrint(td, patch_another_sock, "sys_nmount %llx\n", a2);  
    ps4KernelSocketPrintHexDump(td, patch_another_sock, a2, 0x40);
    uint64_t * points = a2[0];
    char lastkey[1024];
    char curval[1024];
    for (int i=0; i<a2[1]; i++)
    {
        uint64_t isvalue = i % 2;
        if (isvalue == 0)
        {
            bzero(lastkey, 1024);
            copyin(points[0+2*i], lastkey, points[1+2*i]);
        }
        curval[0] = 0;
        copyin(points[0+2*i], curval, points[1+2*i]);
        if (memcmp(curval, "/mnt/sandbox/pfsmnt/CUSA00001-app0", 34) == 0)
        {
            if (memcmp(lastkey, "target", 7) == 0)
            {
                copyout("/data/app2", points[0+2*i], 23);
            }
        }
        ps4KernelSocketPrint(td, patch_another_sock, "%s %llx\n", 
                points[0+2*i],
                points[1+2*i]);
    }
    
    //socketprintsection(td, "userspace\n", a2[6], 0x20);
    
    return sys_nmount(a1, a2);
}

int main(int argc, char **argv)
{

    struct thread *td;
    struct socket *client;

    Ps4KernelFunctionHook *h;
    int r;

    if(ps4KernelIsInKernel() != PS4_OK)
    {
        printf("This is not a user space application.\n");
        return PS4_ERROR_IS_KERNEL_ELF;
    }

    ps4KernelThreadGetCurrent(&td);

    //sock = ps4KernelSocketCreate(td, sock, PF_INET, 2, IPPROTO_TCP)

    r = ps4KernelSocketTCPServerCreateAcceptThenDestroy(td, &client, SERVER_PORT);

    patch_another_sock = client;

    uint64_t * cur_stack;

    __asm__(
    "mov %%rbp, %0" 
        : "=r" (cur_stack) :
    );
    ps4KernelSocketPrint(td, patch_another_sock, "stack: %llx %llx, %llx\n", cur_stack[0], cur_stack[1], cur_stack[2]);

    //uint64_t mybuffer = malloc(1024 * 1024);
    //ps4KernelSocketPrint(td, sock, "allocated data buffer: %llX\n", mybuffer);


    uint64_t activate_self_info = 0xffffffff82647030;

    uint64_t exec_self_imgact = 0xffffffff82649940; //doesn't have symbol

    solveprint_symbol(td, client, "self_orbis_sysvec");

    solveprint_symbol(td, client, "VOP_UNLOCK_APV");
    //solveprint_symbol(td, client, "vm_map_unlock");

    r_sys_mprotect = solveprint_symbol(td, client, "sys_mprotect");
    r_sys_dynlib_dlsym = solveprint_symbol(td, client, "sys_dynlib_dlsym");
    r_sys_open = solveprint_symbol(td, client, "sys_open");

    getoffset(td,client);

    solveprint_symbol(td, client, "exec_new_vmspace");
    solveprint_symbol(td, client, "_vm_map_lock");
    solveprint_symbol(td, client, "_vm_map_unlock");
    solveprint_symbol(td, client, "vm_object_reference");
    solveprint_symbol(td, client, "vm_map_insert");
    solveprint_symbol(td, client, "vm_object_deallocate");
    solveprint_symbol(td, client, "_vn_lock");
    uint64_t NDINIT = solveprint_symbol(td, client, "_NDINIT");
    uint64_t NDFREE = solveprint_symbol(td, client, "NDFREE");
    uint64_t namei = solveprint_symbol(td, client, "namei");
    uint64_t NDHASGIANT = solveprint_symbol(td, client, "_NDHASGIANT");
    

    uint64_t printf_ref = solveprint_symbol(td, client, "printf");

    uint64_t exec_shell_imgact = solveprint_symbol(td, client, "exec_shell_imgact"); //1.76 0xffffffff82e39d30;
    uint64_t dynlib_proc_initialize_step3 = solveprint_symbol(td, client, "dynlib_proc_initialize_step3");
    uint64_t panic = solveprint_symbol(td, client, "panic");

    ps4KernelProtectionWriteDisable();

    //r = ps4KernelSocketPrintHexDump(td, client, justanother_imgact, 0x60);

    uint64_t first_syscall_fptr = 0xffffffff83231638 - 308 * 48;

    *(uint64_t*)(0xffffffff8322e068) = hook_sys_mount;
    *(uint64_t*)(0xffffffff83232358) = hook_sys_nmount;

    *(uint64_t*)(0xffffffff83263f60) = hook_self_imgact;
    *(uint64_t*)(0xffffffff83263ed8) = hook_exec_set_regs;
    *(uint64_t*)(0xffffffff83234bd8) = hook_sys_dynlib_load_prx;

    *(uint64_t*)(0xffffffff8322e788) = hook_sys_execve;


    //*(uint64_t*)(0xffffffff8322dd68) = sycall_hook_open;

    //should be on stage2 only    
    //*(uint64_t*)(0xffffffff8322ea58) = hook_sys_mprotect;
//  *(uint64_t*)(0xffffffff8322ea60) = 0;


    //need a customsyscall to write mem
    //sys_kldstat (308)
    *(uint64_t*)(0xffffffff83231630) = 6;
    *(uint64_t*)(0xffffffff83231638) = custom_sycall_gate;
    //*(uint64_t*)(0xffffffff8322e918) = 0x100000001;

    //*(uint64_t*)(first_syscall_fptr + 0x24f * 48) = sycall_hook_dlsymbol_resolv;

    //null getattr and access checks on exec_check_permissions
    for (uint64_t i=0xffffffff82407147; i< 0xffffffff824071ce; i++) 
        *(uint8_t*)i = 0x90;

    //null getattr and access checks on load_sharedobject->do_load
    for (uint64_t i=0xffffffff82648470; i< 0xffffffff826484a0; i++) 
        *(uint8_t*)i = 0x90;
    *(uint8_t*)0xffffffff826484a0 = 0xe9;
    *(uint8_t*)0xffffffff826484df = 14;
    *(uint8_t*)0xffffffff82648599 = 0xeb;

    //one of this patches is making execve fail?
    //will make libkernel load more modules than needed in each proc, including GnmDriver

    // FFFFFFFF82649CDF < xor eax, eax << sceSblRcMgrIsAllowDisablingAslr


    // replacing all the context of this: FFFFFFFF82649A5C call    sceSblAuthMgrIsLoadable
    // FFFFFFFF82649A27 < FFFFFFFF82649A61
    // nop_fill(0xFFFFFFFF82649A27, 0xFFFFFFFF82649A61 - 0xFFFFFFFF82649A27);
    // zero_eax(0xFFFFFFFF82649A27);

    // hook_enter
    // hook might replace the vmpager with cleartext pager


    // FFFFFFFF82649A5C < xor eax, eax
    //jmp_bridge(0xffffffff82649610, &self_slurp_unloadable_segment_hook_asm);

    // *(uint8_t*)(0xffffffff827c67a0) = 0x48;
    // *(uint8_t*)(0xffffffff827c67a1) = 0x31;
    // *(uint8_t*)(0xffffffff827c67a2) = 0xc0;
    // *(uint8_t*)(0xffffffff827c67a3) = 0xc3;

    // *(uint8_t*)(0xffffffff825f5210) = 0xb8;
    // *(uint8_t*)(0xffffffff825f5211) = 0x01;
    // *(uint8_t*)(0xffffffff825f5212) = 0x00;
    // *(uint8_t*)(0xffffffff825f5213) = 0x00;
    // *(uint8_t*)(0xffffffff825f5214) = 0x00;
    // *(uint8_t*)(0xffffffff825f5215) = 0xc3;

    // *(uint8_t*)(0xffffffff825f5200) = 0xb8; //hasmmapselfcapability, need return 1
    // *(uint8_t*)(0xffffffff825f5201) = 0x01;
    // *(uint8_t*)(0xffffffff825f5202) = 0x00;
    // *(uint8_t*)(0xffffffff825f5203) = 0x00;
    // *(uint8_t*)(0xffffffff825f5204) = 0x00;
    // *(uint8_t*)(0xffffffff825f5205) = 0xc3;

    // *(uint64_t*)(0xffffffff83263f60) = probe;

    //memcpy(exec_self_imgact, justanother_imgact, size);
    //bcopy(activate_self_info_patch, fn2, size);


    //r = ps4KernelSocketPrintHexDump(td, client, exec_self_imgact, 0x60);

    // char jmp_panicuint64_t getoffset(struct thread *td, struct socket * sock){ struct  internal_state  imgp; = {0x48, 0xbb, 1,2,3,4,5,6,7,8, 0xff, 0xe3};
    // *(uint64_t*)&(jmp_panic[2]) = panic_hook;
    // memcpy(panic, jmp_panic, 12);


    // char mark_flaguint64_t getoffset(struct thread *td, struct socket * sock){ struct  internal_state  imgp; = {
    //  //0x48, 0xbb, 1,2,3,4,5,6,7,8, //mov rbx, addr
    //  //0x48, 0xc7, 0x30, 0x01, 0x00, 0x00, 0x00, //mov [rbx], 1
    //  0xf3, 0x90,
    //  0xeb, 0xfc,
    //  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

    //*(uint64_t*)&(mark_flag[2]) = (uint64_t)&flag;

    char jmp_probeuint64_t getoffset(struct thread *td, struct socket * sock){ struct  internal_state  imgp; = {0x49, 0xbb, 1,2,3,4,5,6,7,8, 0x41, 0xff, 0xe3, 0x90};
    *(uint64_t*)&(jmp_probe[2]) = (uint64_t)printf_hook;

    // char jmp_probeuint64_t getoffset(struct thread *td, struct socket * sock){ struct  internal_state  imgp; = {0xe8, 0x08, 0x00, 0x00, 0x00, 1,2,3,4,5,6,7,8, 0x41, 0x5b, 0x41, 0xff, 0x23};
    // *(uint64_t*)&(jmp_probe[5]) = (uint64_t)probe;

    //too much chance of crashing at start time just for some dbg output
    // would be good if can adquire the GIANT lock here
    // if (memcmp(jmp_probe, printf_ref, 14) != 0)
    //  bcopy(jmp_probe, printf_ref, 14);

    __sync_synchronize();

    ps4KernelProtectionWriteEnable();

    ps4KernelSocketPrint(td, patch_another_sock, "started sucessfully\n");

    while (1)
    {
        pause("hooked", 500);
        if (flag == 1)
        {
            ps4KernelSocketPrint(td, patch_another_sock, "flag got updated!\n");
            flag = 0;
        }
    }

    ps4KernelSocketPrint(td, patch_another_sock, "exiting!\n");

    return PS4_OK;

}




