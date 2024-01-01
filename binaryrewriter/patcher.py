import lief
import os


class Patcher():
    def __init__(self, filepath):
        self.filepath = filepath
        self.validate_elf()
        self.binary = self.load_binary()

    def load_binary(self):
        try:
            return lief.parse(self.filepath)
        except Exception as e:
            raise Exception(f"Error: Failed to load binary file: {e}")

    def validate_elf(self):
        with open(self.filepath, "rb") as file:
            magic_number = file.read(4)
            if magic_number != b'\x7fELF':
                raise Exception("Error : File is not ELF")

            file.seek(4)
            ei_class, ei_data = file.read(2)
            if ei_class != 1:
                raise Exception("Error : ELF is not for 32-bit architecture")

            file.seek(18)
            e_machine = file.read(2)
            if e_machine != b'\x28\x00':
                raise Exception("Error : ELF is not for ARM architecture")

    def save_binary(self, new_filepath=None):
        if new_filepath is None:
            new_filepath = self.filepath + "_mod"
        self.binary.write(new_filepath)
        print("Modified file saved to:", new_filepath)

    def find_function_address(self, function_name):
        # 주어진 함수의 주소를 찾는 함수
        for symbol in self.binary.symbols:
            if symbol.name == function_name:
                return symbol.value
        raise ValueError("Function not found.")

    def find_function_symbol(self, function_name):
        # 주어진 함수의 심볼을 찾는 함수
        for symbol in self.binary.symbols:
            if symbol.name == function_name:
                return symbol
        raise ValueError("Function not found.")

    def find_function_name(self, address):
        # 주어진 주소에 위치한 함수의 이름을 찾는 함수
        for symbol in self.binary.symbols:
            if symbol.value == address and symbol.type == lief.ELF.SYMBOL_TYPES.FUNC:
                return symbol.name

        return "Function not found at the given address"

    def patch_by_function_name(self, function_name, new_bytes):
        # 주어진 함수의 주소를 찾아서 패치하는 함수
        function_address = self.find_function_address(function_name)
        if function_address is None:
            print("Error: Function not found.")
            return
        self.binary.patch_address(function_address, new_bytes)

    def extract_functions(self, function_names):
        # 주어진 함수의 코드를 추출하는 함수
        functions_data = []
        for name in function_names:
            symbol = self.binary.get_symbol(name)
            start_addr = symbol.value
            code = self.binary.get_content_from_virtual_address(start_addr, symbol.size)
            functions_data.append((name, start_addr, symbol.size, code))

        return functions_data

    def insert_functions_to_new_section(self, section_name, functions):
        # 새 섹션을 생성하고 여러 함수를 삽입하는 함수
        new_section = lief.ELF.Section(f".{section_name}")
        new_section.type = lief.ELF.SECTION_TYPES.PROGBITS
        new_section.flags = lief.ELF.SECTION_FLAGS.ALLOC | lief.ELF.SECTION_FLAGS.EXECINSTR
        new_section.alignment = 0x10
        new_section.virtual_address = 0x700000

        # 섹션 내용 준비
        section_content = bytearray()
        for _, _, _, code in functions:
            section_content += bytes(code)

        new_section.content = list(section_content)

        shadow_section = lief.ELF.Section(".shadow")
        shadow_section.virtual_address = 0x20000000
        shadow_section.size = 0xA00000
        shadow_section.type = lief.ELF.SECTION_TYPES.PROGBITS
        shadow_section.flags = lief.ELF.SECTION_FLAGS.ALLOC | lief.ELF.SECTION_FLAGS.WRITE
        shadow_section.content = memoryview(b'0' * shadow_section.size)

        # 새 섹션을 바이너리에 추가
        self.binary.add(new_section)
        self.binary.add(shadow_section)
        self.save_binary()
        self.binary = lief.parse(self.filepath + "_mod")

        # .text 섹션을 새로 추가했으므로 두번째 .text 섹션을 찾음
        text_sections = [section for section in self.binary.sections if section.name == ".text"]
        if len(text_sections) < 2:
            raise ValueError("Second .text section not found")

        # 새 섹션의 실제 가상 주소 계산
        new_section_va = text_sections[1].virtual_address

        # 각 함수에 대한 심볼 생성 및 추가
        current_va = new_section_va
        for name, _, size, _ in functions:
            new_symbol = lief.ELF.Symbol()
            new_symbol.name = name
            new_symbol.value = current_va
            new_symbol.size = size
            new_symbol.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL
            new_symbol.type = lief.ELF.SYMBOL_TYPES.FUNC

            self.binary.add_static_symbol(new_symbol)
            current_va += size

        self.save_binary()
        self.print_symbol() # 심볼이 잘 추가되었는지 확인
        return new_section_va

    def print_symbol(self):
        for symbol in self.binary.symbols:
            print(symbol)

    def calculate_file_offset(self, virtual_address):
        # 가상 주소가 속한 섹션 또는 세그먼트 찾기
        for segment in self.binary.segments:
            if segment.virtual_address <= virtual_address < segment.virtual_address + segment.physical_size:
                # 가상 주소에 해당하는 파일 오프셋 계산
                offset_in_segment = virtual_address - segment.virtual_address
                return segment.file_offset + offset_in_segment

        raise ValueError("주어진 가상 주소에 해당하는 세그먼트를 찾을 수 없습니다.")

    def extract_bytes(self, src_address, num_bytes):
        src_offset = self.calculate_file_offset(src_address)
        with open(self.filepath, 'rb') as f:
            # 파일에서 원하는 주소에서 바이트 읽기
            f.seek(src_offset)
            src_bytes = f.read(num_bytes)

        return src_bytes

    def insert_bytes(self, dest_address, src_bytes):
        dest_offset = self.calculate_file_offset(dest_address)
        with open(self.filepath+"_mod", 'r+b') as f:
            # 파일에서 원하는 주소에 바이트 붙여넣기
            f.seek(dest_offset)
            f.write(src_bytes)