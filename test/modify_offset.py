from binaryrewriter.reassembler import Reassembler

# 함수 추출 대상 바이너리 파일
source = Reassembler("{filepath}")
# 수정 대상 바이너리 파일
binary = Reassembler("{filepath}")

# 수정 대상 함수 이름
function_names = ["heap_to_shadow", "asan_malloc", "asan_free", "asan_check", "asan_calloc", "asan_realloc", "is_asan_target", "closest", "handler", "asan_init"]

tmp = []
for name in function_names:
    tmp.append([name])

for function_name in tmp:
    original_data = source.extract_functions(function_name)
    patched_data = binary.extract_functions(function_name)
    _, original_address, original_size, _ = original_data[0]
    _, patched_address, patched_size, _ = patched_data[0]

    original = source.disassemble_from_address(original_address, original_size)
    patched = binary.disassemble_from_address(patched_address, patched_size)

    for ori, patch in zip(original, patched):
        print(f"{hex(ori.address)}: {ori.mnemonic} {ori.op_str}")
        print(f"{hex(patch.address)}: {patch.mnemonic} {patch.op_str}")

        if (ori.mnemonic == 'bl') & (ori.op_str != patch.op_str):
            hex_part = ori.op_str[3:]
            search_address = int(hex_part, 16)
            print("Search address:", hex(search_address))

            original_function_name = source.find_function_name(search_address)
            print("Original function name:", original_function_name, "\n")
            if original_function_name == "__free":
                original_function_name = "free"
            elif original_function_name == "__printf":
                original_function_name = "printf"

            address_to_insert = binary.find_function_address(original_function_name)
            address_to_modify = patch.op_str[3:]
            print("Address to insert:", hex(address_to_insert))

            binary.patch_bl_instruction(patch.address, address_to_insert)
            print("Function call is modified.\n")