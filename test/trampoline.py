from binaryrewriter.trampoliner import Trampoline

# 함수 추출 대상 바이너리 파일
source = Trampoline("{filepath}")
# 트램폴린 구현 대상 바이너리 파일
binary = Trampoline("{filepath}")


# 트램폴린 패치를 위해 추출할 함수 이름
function_name = "asan_init"
section_name = "text"

trampoline_address = 0x1af34
target_address = 0x7006a0
function_address = binary.find_function_address(function_name)

binary.save_binary()

extracted_bytes = binary.extract_bytes(trampoline_address, 4)
binary.insert_bytes(target_address, extracted_bytes)

binary.patch_bl_instruction(trampoline_address, target_address)
binary.register_push(target_address+4)
binary.patch_bl_instruction(target_address+8, function_address)
binary.register_pop(target_address+12)
