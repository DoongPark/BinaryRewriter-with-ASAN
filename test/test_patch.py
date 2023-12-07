from binaryrewriter.patcher import Patcher

# 함수 추출 대상 바이너리 파일
source = Patcher("{filepath}")
# 수정 대상 바이너리 파일
binary = Patcher("{filepath}")

# 패치를 위해 추출할 함수 이름
function_names = ["asan_malloc", "asan_check", "heap_to_shadow"]
section_name = "text"

functions_data = source.extract_functions(function_names)
insert_address = binary.insert_functions_to_new_section(section_name, functions_data)
print("Function is inserted in ", hex(insert_address))
