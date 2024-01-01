# BinaryRewriter
**BinaryRewriter**는 ARM 32-bit ELF 파일을 대상으로 파일의 바이너리를 조작할 수 있도록 도움을 주는 파이썬 소프트웨어입니다.<br>
파이썬 모듈을 사용하는 것과 동일하게 import하여 사용할 수 있으며 다른 파일로부터 함수를 추출하여 삽입, 함수 콜을 후킹하는 등의 기능을 수행할 수 있습니다.<br>
해당 Binary Rewriter는 ASAN과 같은 부가 기능을 패치하여 메모리 버그를 포함한 취약점을 찾는데도 이용할 수 있고, 취약점을 발생시키는 함수를 새로운 함수로 대체하여 취약점을 패치하는 데도 이용할 수 있습니다.<br>
### 왜 ARM 32-bit인가?
ARM 32-bit는 IoT 기기의 임베디드 펌웨어로 많이 사용되는 아키텍처입니다. IoT 기기는 제조사의 지원이 끝나거나 제조사가 사라진 경우, 기기에 취약점이 발견되어도 공식 패치를 제공받기 어려워지므로 구형 모델 사용자들을 위한 취약점 패치가 따로 필요합니다. <br>
따라서 해당 Binary Rewriter가 제작되었으며 ARM 32-bit를 대상으로 하는 이유입니다. 임베디드 펌웨어가 아니더라도 ARM 32-bit 아키텍처로 컴파일 된 ELF 파일을 대상으로 어디든지 이용할 수 있습니다.

## Address Sanitizer (ASAN)
**Address Sanitizer**는 메모리 버그와 관련된 프로그램 오류를 식별하고 디버깅하는 데 도움을 주는 분석도구이며 C 및 C++ 프로그래밍 언어로 작성된 프로그램에서 발생하는 메모리 오류를 검출하는데 사용됩니다.
이를 적용함으로써 다음과 같은 문제를 해결할 수 있습니다.

예시
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
- 본 ASAN은 array 전후로 redzone을 두고, redzone에 접근하려고 하면 에러를 내는 방식으로 **heap overflow**를 검출하도록 설계되었습니다.
- [asan.c](asan/asan.c)의 asan_malloc 함수는 일반 malloc과는 다르게 메모리를 할당하면서 array 전후로 redzone을 두며, redzone에 접근을 시도할 경우 heap overflow 발생을 사용자에게 알립니다.

적용 예시 ([asan.c](asan/asan.c) 실행 결과)
```bash
$ ./asan
access a[0]
access a[1]
access a[2]
access a[3]
access a[4]
access a[5]
access a[6]
access a[7]
access a[8]
access a[9]
asan: heap overflow
access a[10]
asan: heap overflow
access a[11]
asan: heap overflow
access a[12]
asan: heap overflow
access a[13]
```

## 파일 구성
### [patcher.py](binaryrewriter/patcher.py)
- 바이너리 로드, 저장
- ARM 32-bit ELF 파일 여부 검사
- 함수의 이름 입력을 통한 함수의 주소 검색, 함수의 주소 입력을 통한 함수의 이름 검색, 함수 심볼 검색
- bytes 입력을 통한 수동 패치, 이름이 주어진 함수의 바이너리 추출 -> 새로운 섹션을 만들어 삽입 + 함수 심볼 추가 가능
    - 여러개 함수의 다중 패치 가능

### [reassembler.py](binaryrewriter/reassembler.py)
> Apple Silicon Mac(ARM)에서 Reassembler 클래스를 이용하는 경우 capstone에서 오류 발생으로 해당 클래스를 사용하는 경우 Ubuntu 22.04 환경에서 실행하였음
- Patcher 클래스를 상속하는 Reassembler 클래스 이용
- 파일을 주어진 주소로부터 disassemble
- Assembly의 BL 명령(ARM의 점프 명령)을 찾아 함수 실행(function call) 변경
    - .text 섹션(함수 섹션) 전역을 탐색하여 일괄 변경 가능


## 동작
- patcher.py와 reassembler.py를 import하여 함수를 적절하게 이용하여 원하는 방식으로 패치를 진행할 수 있습니다.<br>
- [test](test/) 폴더 내의 `.py` 파일들이 이를 이용하여 패치를 진행하는 예시 코드들입니다. 파일 경로만 변경하여 짜여진 예시 코드 그대로도 사용할 수 있습니다.
---
### ASAN을 이용한 동작 예시
> 다음 과정들은 특정 ARM 32-bit ELF 파일에서 `malloc`을 호출하는 부분을 `asan` 파일 내의 함수인 `asan_malloc`으로 패치해주는 과정입니다.
- [asan](asan/asan)은 [asan.c](asan/asan.c)가 **statically linked** 되어 컴파일된 ELF 실행 파일로 dynamically linked 된 파일을 사용할 경우 malloc과 같은 함수의 call을 찾는데 있어 문제 발생의 여지가 있습니다.
- `source` : 함수 추출 대상 바이너리 파일, `binary` : 패치 대상 바이너리 파일 경로 입력
- `function_name`, `old_function_call`과 같은 변수값만 변경하여 원하는 함수 패치 가능

### [patcy.py](test/patch.py)

<img width="518" alt="스크린샷 2023-12-07 09 38 07" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/c6e51819-02e9-43ae-80e2-324290d9e94d">
<img width="577" alt="스크린샷 2023-12-07 09 38 18" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/d0bde075-1532-499c-a9aa-219a526239da">

- 패치 진행시, 완료 후 모든 함수 심볼 목록을 출력하며 함수들이 어디에 패치되었는지를 알 수 있습니다.
- 해당 예시에서는, 새로운 .text 섹션 속 asan_malloc, asan_check, heap_to_shadow가 추가되었습니다.

<img width="475" alt="스크린샷 2023-12-06 02 31 57" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/f3a3cfba-5987-40ab-8ac5-1d1ed5aa41c4">
<img width="476" alt="스크린샷 2023-12-06 02 30 52" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/e886efe1-ed10-4c3b-9c5d-841e89004bbb">

- 전 : 패치 진행전 ELF 파일의 섹션 목록
- 후 : test_patch.py 코드 실행 후 새로운 .text 섹션이 추가된 모습
  
<img width="609" alt="스크린샷 2023-12-06 02 33 22" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/df950cb8-d1c3-4678-b651-e3906c2f6185">

- 추가된 섹션에 asan_malloc, asan_check, heap_to_shadow 함수 패치가 진행된 모습
- relative offset으로 점프를 수행하는 BL 명령 특성상 asan_malloc 내에서 malloc, memset과 같은 함수들을 호출하는 부분에서 문제가 발생
- 따라서 새로운 함수 삽입 시, 해당 함수 내부에서 다른 함수를 call 하는 부분에 대해 추가 패치 필요

### [modify_offset.py](test/modify_offset.py)

<img width="335" alt="스크린샷 2023-12-06 03 09 17" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/d86ab992-3465-4901-b944-3148cbf95128">

- 지정한 함수의 주소부터 disassemble하여 Assembly를 출력하며 BL 명령이 발견되면, 함수를 추출하는데 사용한 source 객체(기존 바이너리)에서 해당 BL 명령의 relative offset이 어디를 가리키는지 계산하여 어떤 함수를 가리키는지 찾습니다.
- 찾아낸 함수와 동일한 함수의 주소를 binary 객체(새로운 바이너리)에서 찾아, relative offset을 계산하여 BL 명령에 패치합니다.
- 해당 예시에서는, asan_malloc 속 malloc, memset, asan_check의 relative offset을 새로 계산하여 패치합니다.

<img width="600" alt="스크린샷 2023-12-06 02 47 03" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/109cf062-3d4d-4052-a5e5-2822b16ef1d8">

- test_patch.py만을 실행했을 때와 달리, BL malloc이 정상적으로 수행되는 모습

### [hook_function_call.py](test/hook_function_call.py)

<img width="323" alt="스크린샷 2023-12-06 03 10 45" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/6c258567-4169-4eaf-9df1-a44eb4c331c3">

- 지정한 섹션을 순회하며 지정한 함수를 가리키는 BL 명령을 찾습니다.
- 이동시키고자 하는 새로운 함수의 주소와 relative offset을 계산하여 BL 명령을 변경합니다.
- 해당 예시에서는, BL malloc을 BL asan_malloc으로 변경하는 후킹을 수행합니다.

<img width="460" alt="스크린샷 2023-12-06 02 51 15" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/c193c33b-8b82-4439-aa90-7ed4d9a3883f">
<img width="460" alt="스크린샷 2023-12-06 02 56 30" src="https://github.com/DoongPark/BinaryRewriter-with-ASAN/assets/77007815/55cf4912-aff4-4e58-8dbe-d04a6255d4c2">

- 전 : 패치 전, 기존 malloc을 실행하는 모습
- 후 : 패치 후, function call을 후킹하여 앞서 패치했던 asan_malloc의 주소로 이동시키는 모습

## Reference
[LIEF Documentation](https://lief-project.github.io/)<br>
[Capstone](http://www.capstone-engine.org)<br>
[Address Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)

## License
본 프로젝트는 MIT 라이선스를 따릅니다 - 자세한 내용은 [LICENSE](LICENSE)를 참고해주세요.
