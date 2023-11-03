#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

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
  //struct map *mm;

  int length, prot, flags, fd, offset, addr;

  // if(argptr(0, (void*)&addr, sizeof(*addr))
  if(argint(0, &addr) < 0 || argint(1, &length) < 0 || argint(2, &prot) < 0 || 
  argint(3, &flags) < 0 || argint(4, &fd) < 0 || argint(5, &offset) < 
  0)
    return -1;
    //return (void *)-1;

  // if(flags != MAP_ANON) {
  //   // Do file based memory mapping
  // }

  // if((flags & (MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED)) != (MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED))
  //   //return (void*)-1;
  //   return -1;

  if(addr < 0x60000000 || addr > 0x80000000)
    //return (void*)-1;
    return -1;

  //return 0;


  //int pages = PGROUNDUP(length);

  char *mem = kalloc();

  struct proc *curproc = myproc();

  if(mappages(curproc->pgdir, (void*)addr, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0){
    cprintf("allocuvm out of memory (2)\n");
    kfree(mem);
    return 0;
  }
  
  // for(int i=0; i<pages; i++) {
  //   mem = kalloc();
  //   if(mem == 0){
  //     cprintf("allocuvm out of memory\n");
  //     //deallocuvm(pgdir, newsz, oldsz);
  //     return 0;
  //   }
  //   memset(mem, 0, PGSIZE);
  //   if(mappages(pgdir, (char*)a, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0){
  //     cprintf("allocuvm out of memory (2)\n");
  //     deallocuvm(pgdir, newsz, oldsz);
  //     kfree(mem);
  //     return 0;
  //   }
  // }

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

  return 0;
}
