#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define REDZONE_SIZE 32
#define REDZONE_PATTERN 0xfb

unsigned long OFFSET = 0;
unsigned int *shadow;

void* heap_to_shadow(void* addr) {
    return ((unsigned long)addr >> 3) + OFFSET;
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
    return mem + REDZONE_SIZE;
}

void asan_check(void* addr, int offset) {
    unsigned char *shadow_addr = (unsigned char*)heap_to_shadow(addr + offset); 
    if (*shadow_addr == 0xff || (*shadow_addr != 0x00 && *shadow_addr <= offset % 8)) {
        printf("asan: heap overflow\n");
    }
}

int main() {
    shadow = (unsigned int*)malloc(1024);
    OFFSET = (unsigned long)(shadow) - ((unsigned long)(shadow + 1024) >> 3);

    char* a = (char*)asan_malloc(10);
    for (int i = 0; i < 14; i++) {
        asan_check(a, i);
        printf("access a[%d]\n", i);
        a[i] = 42; // heap overflow
    }
    return 0;
}
