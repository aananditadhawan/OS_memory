/* Define mmap flags */
#define MAP_PRIVATE 0x0001
#define MAP_SHARED 0x0002
#define MAP_ANONYMOUS 0x0004
#define MAP_ANON MAP_ANONYMOUS
#define MAP_FIXED 0x0008
#define MAP_GROWSUP 0x0010

/* Protections on memory mapping */
#define PROT_READ 0x1
#define PROT_WRITE 0x2

struct map {
    void *addr;
    int length; 
    int prot;
    int flags; 
    int fd;
    int offset;
    int guard;
    // int childStart;
    // int childEnd;
    //int acquired;
    int pid;
    char *physicalM;
    //char *buff;
};
