#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include <stddef.h>
//#include "file.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

static pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;

  a = (char*)PGROUNDDOWN((uint)va);
  last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
  for(;;){
    if((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if(*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

int sys_mmap(void) {

  int length, prot, flags, fd, offset, addr;

  if(argint(0, &addr) < 0 || argint(1, &length) < 0 || argint(2, &prot) < 0 || 
  argint(3, &flags) < 0 || argint(4, &fd) < 0 || argint(5, &offset) < 
  0)
    return -1;

  cprintf("what did we get ? addr=%d, length=%d, prot=%d, flags=%d, fd=%d, offset=%d \n", 
  addr, length, prot, flags, fd, offset);

  // if((flags & (MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED)) != (MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED))
  //   return -1;

  if((addr < 0x60000000 || addr > 0x80000000) && (flags & MAP_FIXED) == MAP_FIXED)
    //return (void*)-1;
    return -1;

  //int pages = PGROUNDUP(length);

  struct proc *curproc = myproc();

  if((flags & MAP_FIXED) != MAP_FIXED) {
    //addr = 0x60000000; // check an empty space from the mapping here
    //int chosenIdx = -1;
    //if(((int)curproc->mapping[0]->addr - 0x60000000) > length){
    if(curproc->lastUsedIdx==-1) {
      // map at the beginning
      //chosenIdx = ++curproc->lastUsedIdx;
      addr = 0x60000000;
    } else{
      for(int i = 0; i < 32; i++){
        if(i<curproc->lastUsedIdx){
          int straddr = (int)curproc->mapping[i]->addr + curproc->mapping[i]->length;
          if(i==curproc->lastUsedIdx) {
            //chosenIdx=++curproc->lastUsedIdx;
            addr=straddr;
            break;
          }
          
          int dif = (int)curproc->mapping[i+1]->addr - length;
          if(dif > straddr){
	    // map
            //chosenIdx=++curproc->lastUsedIdx;
            addr = straddr;
            break;
	      }
        } else {
          addr = (int)curproc->mapping[i-1]->addr + curproc->mapping[i-1]->length;
        }
      }      
    }
  }

  char *mem = kalloc(); // needed for file backed as well

  if(mappages(curproc->pgdir, (void*)addr, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0){
    cprintf("allocuvm out of memory (2)\n");
    kfree(mem);
    return -1;
  }
  
  // fd , offset , write from file to memory 

  // cprintf("here from mmap - i am doin okay");

  // cprintf("initial mapping");

  // for(int i=0; i<32; i++) {
  //   //if(curproc->mapping[i]->addr != 0) {
  //     cprintf("index=%d, addr=%d, length=%d, prot=%d, flags=%d, fd=%d, offset=%d \n", i, (int)curproc->mapping[i]->addr,
  //     curproc->mapping[i]->length, curproc->mapping[i]->prot, curproc->mapping[i]->flags,
  //     curproc->mapping[i]->fd, curproc->mapping[i]->offset);
  //   //}
  // }

  int idx = ++curproc->lastUsedIdx;

  curproc->mapping[idx]->addr=(void *)addr;
  curproc->mapping[idx]->length=length;
  curproc->mapping[idx]->prot=prot;
  curproc->mapping[idx]->flags=flags;
  curproc->mapping[idx]->fd=fd;
  curproc->mapping[idx]->offset=offset;

  cprintf("%d was changed\n", idx);

  // for(int i=0; i<32; i++) {
  //   //if(curproc->mapping[i]->addr != NULL) {
  //     cprintf("index=%d, addr=%d, length=%d, prot=%d, flags=%d, fd=%d, offset=%d \n", i, (int)curproc->mapping[i]->addr,
  //     curproc->mapping[i]->length, curproc->mapping[i]->prot, curproc->mapping[i]->flags,
  //     curproc->mapping[i]->fd, curproc->mapping[i]->offset);
  //   //}
  // }

  cprintf("addr is %d\n", addr);

  if((flags & MAP_ANON) != MAP_ANON) {
    // file backed
    if(curproc->ofile[fd]){
      cprintf("file exists\n");
      int rv;
      // int rv = filewrite(curproc->ofile[fd], (char *)addr, length);
      // cprintf("return value of file write is %d\n", rv);
      rv = fileread(curproc->ofile[fd], (char *)addr, length);
      cprintf("return value of file read is %d\n", rv);
      cprintf("read from the file is %s\n", (char *)addr);
    } else {
      cprintf("file doesnt exis\n"); 
    }
  }

  return addr;
}

int sys_munmap(void) {

  int addr, length;
  if(argint(0, &addr) < 0 || argint(1, &length) < 0)
    return -1;

  // Check if address is within valid range (similar check as in sys_mmap)
  if(addr < 0x60000000 || addr > 0x80000000)
    return -1;

  struct proc *curproc = myproc();

  // find the write file if there is something associated -> that means during unmap, we need to write back
  for(int i = 0; i < 32; i++){
        cprintf("idx = %d, addr = %d, fd = %d\n", i, curproc->mapping[i]->addr, curproc->mapping[i]->fd);
        cprintf("last used idx = %d\n", curproc->lastUsedIdx);
        if(i<=curproc->lastUsedIdx){
          if((int)curproc->mapping[i]->addr == addr && curproc->mapping[i]->fd != 0) {
            int fd = curproc->mapping[i]->fd;
            // struct file* file = curproc->ofile[fd];
            // file->off = 0;
            // curproc->ofile[fd] = file;
            //curproc->ofile[fd]->off = 0;
            if((curproc->mapping[i]->flags & MAP_SHARED) == MAP_SHARED) {
              int rv;
              rv = filewrite(curproc->ofile[fd], (char *)addr, length);
              cprintf("return value of file write is %d\n", rv);  
            }
            break; 
          }
        }
  }

  // Calculate the number of pages to remove based on the provided length.
  int pages = PGROUNDUP(length) / PGSIZE;

  for(int i = 0; i < pages; i++) {
    char* va = (char*)(addr + i*PGSIZE);
    pte_t *pte;
    int pa;

    // Get the page table entry
    pte = walkpgdir(curproc->pgdir, va, 0);
    if(!pte || (*pte & PTE_P) == 0) {
      continue; // No mapping exists for this page.
    }

    pa = PTE_ADDR(*pte);

    // Deallocate the physical page.
    kfree((char*)P2V(pa));

    // Clear the page table entry
    *pte = 0;

  }

  // write from buffer in memory to file 

  //cprintf("here from munmap - i am doin okay too");

  return 0;
}

