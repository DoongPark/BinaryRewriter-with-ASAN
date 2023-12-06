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
asan_malloc 함수는 일반 malloc과는 다르게 메모리를 할당하면서 redzone도 같이 할당하며 asan_check 함수로 heap overflow 여부를 체크합니다.

## 파일 구성
[patcher.py](patchery.py)
- 바이너리 로드, 저장
- ARM 32-bit ELF 파일 여부 검사
- 함수의 이름 입력을 통한 함수의 주소 검색, 함수의 주소 입력을 통한 함수의 이름 검색, 함수 심볼 검색
- bytes 입력을 통한 수동 패치, 이름이 주어진 함수의 바이너리 추출 -> 새로운 섹션을 만들어 삽입 + 함수 심볼 추가 가능
    - 여러개 함수의 다중 패치 가능

[reassembler.py](reassembler.py)
- 주어진 주소로부터 disassemble
- Assembly의 bl 명령(ARM의 점프 명령)을 찾아 함수 실행(function call) 변경
    - .text 섹션(함수 섹션) 전역을 탐색하여 일괄 변경 가능


## 동작
> 다음 과정들은 특정 ARM 32-bit ELF 파일에서 `malloc`을 호출하는 부분을 `asan` 파일 내의 함수인 `asan_malloc`으로 패치해주는 과정입니다.

**공통사항**
- `source` : 함수 추출 대상 바이너리 파일, `binary` : 패치 대상 바이너리 파일 경로 입력
- `function_name`, `old_function_call`과 같은 변수값만 변경하여 원하는 함수 패치 가능
- [asan](ASAN/asan)은 [asan.c](ASAN/asan.c)가 **statically linked** 되어 컴파일된 ELF 실행 파일로 dynamically linked 된 파일을 사용할 경우 malloc과 같은 함수의 call을 찾는데 있어 문제 발생의 여지가 있음

[test_patcy.py](test/test_patch.py)

<img width="475" alt="스크린샷 2023-12-06 02 31 57" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/f3a3cfba-5987-40ab-8ac5-1d1ed5aa41c4">
<img width="476" alt="스크린샷 2023-12-06 02 30 52" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/e886efe1-ed10-4c3b-9c5d-841e89004bbb">

- 좌 : 패치 진행전
- 우 : test_patch.py 코드 실행 후 .text 섹션이 새로 추가된 모습
  
<img width="609" alt="스크린샷 2023-12-06 02 33 22" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/df950cb8-d1c3-4678-b651-e3906c2f6185">

- 새로운 .text 섹션을 추가하고 그곳에 asan_malloc, asan_check, heap_to_shadow 함수 패치를 진행
- 하지만 상대적인 offset으로 점프를 수행하는 bl 명령 특성상 asan_malloc 내에서 malloc, memset과 같은 함수들을 호출하는 부분이 꼬임

[test_disassemble.py](test/test_disassemble.py)

<img width="335" alt="스크린샷 2023-12-06 03 09 17" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/d86ab992-3465-4901-b944-3148cbf95128">
<img width="600" alt="스크린샷 2023-12-06 02 47 03" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/109cf062-3d4d-4052-a5e5-2822b16ef1d8">

- 패치된 부분을 disassemble하여 bl 명령이 존재하는 곳을 찾고 추출해낸 source 파일에서의 function call과 비교
- source 파일에서 찾아낸 해당하는 함수 이름을 통해 대상 binary 파일 내에서 그 함수의 주소를 탐색
- 상대적 offset을 계산하는 과정을 거쳐 bl 명령을 올바르게 패치

[test_hooking.py](test/test_hooking.py)

<img width="323" alt="스크린샷 2023-12-06 03 10 45" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/6c258567-4169-4eaf-9df1-a44eb4c331c3"><br>
<img width="460" alt="스크린샷 2023-12-06 02 51 15" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/c193c33b-8b82-4439-aa90-7ed4d9a3883f">
<img width="460" alt="스크린샷 2023-12-06 02 56 30" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/55cf4912-aff4-4e58-8dbe-d04a6255d4c2">

- 좌 : 패치 전, 기존 malloc을 실행하는 모습
- 우 : 패치 후, function call을 후킹하여 앞서 패치했던 asan_malloc의 주소로 이동시키는 모습
- malloc의 주소와 offset 계산을 통해 malloc을 호출하는 부분이라고 찾으면 asan_malloc의 주소와 offset을 계산하여 해당 부분 수정

## Reference
[LIEF Documentation](https://lief-project.github.io/)
[Capstone](http://www.capstone-engine.org)

## License
본 프로젝트는 MIT 라이선스를 따릅니다 - [LICENSE](LICENSE)
