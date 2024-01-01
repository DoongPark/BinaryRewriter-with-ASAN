#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define REDZONE_SIZE 32
#define REDZONE_PATTERN 0xfb
#define OFFSET 0x20000000
#define SHADOW_MEM_SIZE 1024*1024*10
#define SEGVALUE 0x20000000

void* heap_to_shadow(void* addr) {
    return ((unsigned long)addr >> 3) + (*(unsigned long*) OFFSET);
}

void* asan_malloc(unsigned int n) {
    // Redzone과 실제 할당할 메모리를 포함한 총 크기 계산
    unsigned int total_size = n + 2 * REDZONE_SIZE;
    unsigned char *mem = malloc(total_size);

    // Redzone 초기화
    memset(mem, REDZONE_PATTERN, REDZONE_SIZE);
    memset(mem + REDZONE_SIZE + n, REDZONE_PATTERN, REDZONE_SIZE);

    // Shadow 메모리 업데이트
    memset(heap_to_shadow(mem), 0xff, REDZONE_SIZE >> 3);
    memset(heap_to_shadow(mem + REDZONE_SIZE), 0x00, n >> 3);
    memset(heap_to_shadow(mem + REDZONE_SIZE + n), 0xff, REDZONE_SIZE >> 3);

    // 추가 바이트에 대한 Shadow 메모리 설정
    unsigned char remaining = n & 0x07; // 할당된 메모리에서 8바이트 단위로 남은 바이트 수
    if (remaining > 0) {
        *((unsigned char*)heap_to_shadow(mem + REDZONE_SIZE) + (n >> 3)) = remaining;
    }

    // 실제 사용자에게 반환할 메모리 주소
    return mem + REDZONE_SIZE - SEGVALUE;
}

void asan_free(void* addr) {
    // 메모리 주소에 해당하는 shadow 메모리를 0xfb로 초기화
    memset(heap_to_shadow(addr - REDZONE_SIZE), 0xfb, (REDZONE_SIZE + sizeof(addr) + REDZONE_SIZE) >> 3);
    // 실제 메모리 해제
    free(addr - REDZONE_SIZE);
}

void asan_check(void* addr) {
    unsigned char *shadow_addr = (unsigned char*)heap_to_shadow(addr);

    if (*shadow_addr == 0xfb) {
        perror("asan: use-after-free\n");
        asm(
            /* exit */
            "mvn r0, #0\n" /* exit status */
            "mov r7, #1\n" /* syscall id */
            "swi #0"
        );
    } else if (*shadow_addr == 0xff) {
        // fprintf(stderr, "asan: heap overflow (0x%x)\n", *shadow_addr);
        perror("asan: heap overflow\n");
        asm(
            /* exit */
            "mvn r0, #0\n" /* exit status */
            "mov r7, #1\n" /* syscall id */
            "swi #0"
        );
    }
}

void* asan_calloc(int n, int size) {
    return asan_malloc(n * size);
}

void* asan_realloc(void* ptr, int size) {
    asan_free(ptr);
    return asan_malloc(size);
}

int is_asan_target(void* addr) {
  return (SEGVALUE & (unsigned int)addr) == SEGVALUE;
}

/* return the closest element's index */
int closest(unsigned long* arr, int len, unsigned long n)
{
    unsigned long diff = __INT_MAX__;
    int ret = -1;
    for (int i = 0; i < len; i++) {
    int cur_diff = arr[i] - n;
    if (cur_diff < diff) {
        ret = i;
        diff = cur_diff;
    }
    }
    return ret;
}

void handler(int nSignum, siginfo_t* si, void* vcontext) {
    if (!is_asan_target((void*)si->si_addr + SEGVALUE)) {
    /* not sanitizable */
    printf("Segmentation fault at %p\n", si->si_addr);
    exit(-1);
    }
    asan_check((void*)si->si_addr + SEGVALUE);

    /* Valid access. Restore the address */
    ucontext_t* context = (ucontext_t*)vcontext;
    unsigned long reg[8] = {
    context->uc_mcontext.arm_r0,
    context->uc_mcontext.arm_r1,
    context->uc_mcontext.arm_r2,
    context->uc_mcontext.arm_r3,
    context->uc_mcontext.arm_r4,
    context->uc_mcontext.arm_r5,
    context->uc_mcontext.arm_r6,
    context->uc_mcontext.arm_r7
    };
    unsigned long* p_reg[8] = {
    &context->uc_mcontext.arm_r0,
    &context->uc_mcontext.arm_r1,
    &context->uc_mcontext.arm_r2,
    &context->uc_mcontext.arm_r3,
    &context->uc_mcontext.arm_r4,
    &context->uc_mcontext.arm_r5,
    &context->uc_mcontext.arm_r6,
    &context->uc_mcontext.arm_r7
    };

    printf("Restore addr %p\n", si->si_addr);
    for (int i = 0; i < 8; i++) {
    printf("r%d: 0x%x\n", i, reg[i]);
    }
    /* 하위 3개비트 = [Rn] */
    int target_reg = *(unsigned long*)(void*)context->uc_mcontext.arm_pc & 0b111;
    /* Assumes the closest address is trying to access */
    // int target_reg = closest(reg, 8, si->si_addr);
    *p_reg[target_reg] += SEGVALUE;
    // context->uc_mcontext.arm_pc++;
}

void asan_init() {
    memset(OFFSET, 0, SHADOW_MEM_SIZE);
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = handler;
    sigaction(SIGSEGV, &action, NULL);
}


int main() {
    asan_init();

    int* x = asan_malloc(10);
    int y = *x;

    return 0;
}