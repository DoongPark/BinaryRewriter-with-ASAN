import os
from capstone import *
from patcher import Patcher


class Reassembler(Patcher):
    def __init__(self, filepath):
        super().__init__(filepath)
        self.filesize = os.path.getsize(self.filepath)

    def disassemble_from_address(self, address, length):
        # 주어진 주소에서 시작하여 특정 길이만큼의 코드를 디스어셈블하는 함수
        code = self.binary.get_content_from_virtual_address(address, length)

        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)  # 아키텍처에 따라 조정
        disassembled = md.disasm(code, address)

        return disassembled

    def find_bl_instructions(self, address):
        # 주어진 주소에서 시작하여 BL 명령어를 찾는 함수
        text_section = self.binary.get_section(".text")
        if text_section is None:
            raise ValueError("'.text' 섹션을 찾을 수 없습니다.")
        section_start = text_section.virtual_address
        section_end = section_start + text_section.size
        section_content = text_section.content

        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        md.detail = True

        bl_instructions = []
        chunk_size = 0x1000  # 디스어셈블용 분할 단위

        self.save_binary()

        for chunk_start in range(section_start, section_end, chunk_size):
            chunk_end = min(chunk_start + chunk_size, section_end)
            code = section_content[chunk_start - section_start:chunk_end - section_start]
            disassembled = md.disasm(code, chunk_start)

            for instruction in disassembled:
                if instruction.mnemonic == 'bl':
                    # 상대 오프셋 계산
                    relative_offset = (address - instruction.address - 8) // 4
                    # 2의 보수 형태로 변환하고 24비트로 마스킹하여 ARM BL 명령어 인코딩
                    if relative_offset < 0:
                        offset_twos_complement = (1 << 24) + relative_offset
                    else:
                        offset_twos_complement = relative_offset

                    target_hex = 0xEB000000 | (offset_twos_complement & 0xFFFFFF)

                    # 파일 오프셋 계산
                    file_offset = self.calculate_file_offset(instruction.address)
                    with open(self.filepath+"_modified", 'rb') as f:
                        f.seek(file_offset)
                        instruction_bytes = f.read(4)
                        file_hex = int.from_bytes(instruction_bytes, byteorder='little')

                    if target_hex == file_hex:
                        bl_instructions.append((instruction.address, instruction.mnemonic, instruction.op_str))

        return bl_instructions

    def calculate_file_offset(self, virtual_address):
        # 가상 주소가 속한 섹션 또는 세그먼트 찾기
        for segment in self.binary.segments:
            if segment.virtual_address <= virtual_address < segment.virtual_address + segment.physical_size:
                # 가상 주소에 해당하는 파일 오프셋 계산
                offset_in_segment = virtual_address - segment.virtual_address
                return segment.file_offset + offset_in_segment

        raise ValueError("주어진 가상 주소에 해당하는 세그먼트를 찾을 수 없습니다.")

    def patch_bl_instruction(self, bl_address, new_target_address):
        # BL 명령어의 파일 오프셋 계산
        file_offset = self.calculate_file_offset(bl_address)

        # 새로운 BL 명령어의 상대 오프셋 계산
        relative_offset = (new_target_address - bl_address - 8) // 4
        # 새로운 BL 명령어 생성
        new_bl_instruction = 0xEB000000 | (relative_offset & 0xFFFFFF)
        # 파일 오프셋으로 이동하여 BL 명령어 수정
        with open(self.filepath+"_modified", 'r+b') as f:
            f.seek(file_offset)
            f.write(new_bl_instruction.to_bytes(4, byteorder='little'))
