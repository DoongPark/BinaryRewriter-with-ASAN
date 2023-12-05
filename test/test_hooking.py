from reassembler import Reassembler

source = Reassembler("asan")
binary = Reassembler("{filepath}")

# 후킹 대상 함수, 후킹 함수
old_function_call = "malloc"
new_function_call = "asan_malloc"

address = binary.find_function_address(old_function_call)
bl_instructions = binary.find_bl_instructions(address)
to_insert = binary.find_function_address(new_function_call)

for addr, mnem, ops in bl_instructions:
    print(f"Address: {hex(addr)}, Instruction: {mnem} {ops}")

    # malloc이 호출되는 부분을 찾아서 asan_malloc으로 수정
    binary.patch_bl_instruction(addr, to_insert)
    print("Function call is modified.\n")
