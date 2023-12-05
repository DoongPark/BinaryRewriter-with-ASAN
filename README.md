# BinaryRewriter
**BinaryRewriter**는 ARM 32-bit ELF 파일을 대상으로 파일의 바이너리를 조작할 수 있도록 도움을 주는 파이썬 소프트웨어입니다.<br>
파이썬 모듈을 사용하는 것과 동일하게 import하여 사용할 수 있으며 다른 파일로부터 함수를 추출하여 삽입, 함수 콜을 후킹하는 등의 기능을 수행할 수 있습니다.<br>
본 프로젝트에서는 ASAN의 적용을 위해 사용되었지만 ARM 32-bit 환경의 ELF 파일이라면 어디든지 적용될 수 있습니다.


### Address Sanitizer (ASAN)
**Address Sanitizer**는 메모리 버그와 관련된 프로그램 오류를 식별하고 디버깅하는 데 도움을 주는 분석도구이며 C 및 C++ 프로그래밍 언어로 작성된 프로그램에서 발생하는 메모리 오류를 검출하는데 사용됩니다.
이를 적용함으로써 다음과 같은 문제를 해결할 수 있습니다.

예시:
```c
#include <stdio.h>

int main() {
  char arr[10] = {0, };
  arr[11] = 42; // buffer overflow
  printf("%d\n", arr[11]); // buffer overflow
  return 0;
}
```

컴파일 및 실행 결과 -> 버그가 있지만 crash가 나지 않아서 잡지 못함

```bash
$ gcc -fno-stack-protector -o test test.c
$ ./test
42
```
본 ASAN은 array 전후로 redzone을 두고, redzone에 접근하려고 하면 에러를 내는 방식으로 **heap overflow**를 검출하도록 설계되었습니다.<br>

## 설명
[test_patcy.py](test/test_patch.py): 


## License
본 프로젝트는 MIT 라이선스를 따릅니다 - [LICENSE](LICENSE)
