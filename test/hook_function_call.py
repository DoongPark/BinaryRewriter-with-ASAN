from binaryrewriter.reassembler import Reassembler

# 함수 추출 대상 바이너리 파일
source = Reassembler("{filepath}")
# 수정 대상 바이너리 파일
binary = Reassembler("{filepath}")

binary.save_binary()

# 후킹 대상 함수, 후킹 함수
old_function_calls = ["malloc", "free", "calloc", "realloc"]
new_function_calls = ["asan_malloc", "asan_free", "asan_calloc", "asan_realloc"]

for old_function_call, new_function_call in zip(old_function_calls, new_function_calls):
    address = binary.find_function_address(old_function_call)
    bl_instructions = binary.find_bl_instructions(address)
    to_insert = binary.find_function_address(new_function_call)

    for addr, mnem, ops in bl_instructions:
        print(f"Address: {hex(addr)}, Instruction: {mnem} {ops}")

        # malloc이 호출되는 부분을 찾아서 asan_malloc으로 수정
        binary.patch_bl_instruction(addr, to_insert, mnem)
        print(f"Function '{old_function_call}' call is modified into '{new_function_call}'.\n")