import os
from capstone import *
from binaryrewriter.patcher import Patcher


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
        md2 = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        md2.detail = True

        bl_instructions = []
        chunk_size = 0x20  # 디스어셈블용 분할 단위

        self.save_binary()

        for chunk_start in range(section_start, section_end, chunk_size):
            chunk_end = min(chunk_start + chunk_size, section_end)
            code = section_content[chunk_start - section_start:chunk_end - section_start]
            disassembled = md.disasm(code, chunk_start)
            disassembled2 = md2.disasm(code, chunk_start)

            for instruction in disassembled:
                if instruction.mnemonic == 'bl' or instruction.mnemonic == 'b' or instruction.mnemonic == 'blx':
                    # 상대 오프셋 계산
                    relative_offset = (address - instruction.address - 8) // 4
                    # 2의 보수 형태로 변환하고 24비트로 마스킹하여 ARM BL 명령어 인코딩
                    if relative_offset < 0:
                        offset_twos_complement = (1 << 24) + relative_offset
                    else:
                        offset_twos_complement = relative_offset

                    if instruction.mnemonic == 'bl':
                        target_hex = 0xEB000000 | (offset_twos_complement & 0xFFFFFF)
                    elif instruction.mnemonic == 'b':
                        target_hex = 0xEA000000 | (offset_twos_complement & 0xFFFFFF)
                    elif instruction.mnemonic == 'blx':
                        target_hex = int.from_bytes(self.blx_call(address - instruction.address), byteorder='little')

                    # 파일 오프셋 계산
                    file_offset = self.calculate_file_offset(instruction.address)
                    with open(self.filepath+"_mod", 'rb') as f:
                        f.seek(file_offset)
                        instruction_bytes = f.read(4)
                        file_hex = int.from_bytes(instruction_bytes, byteorder='little')

                    if target_hex == file_hex:
                        bl_instructions.append((instruction.address, instruction.mnemonic, instruction.op_str))

            for instruction in disassembled2:
                if instruction.mnemonic == 'bl' or instruction.mnemonic == 'b' or instruction.mnemonic == 'blx':
                    # 상대 오프셋 계산
                    relative_offset = (address - instruction.address - 8) // 4
                    # 2의 보수 형태로 변환하고 24비트로 마스킹하여 ARM BL 명령어 인코딩
                    if relative_offset < 0:
                        offset_twos_complement = (1 << 24) + relative_offset
                    else:
                        offset_twos_complement = relative_offset

                    if instruction.mnemonic == 'bl':
                        target_hex = 0xEB000000 | (offset_twos_complement & 0xFFFFFF)
                    elif instruction.mnemonic == 'b':
                        target_hex = 0xEA000000 | (offset_twos_complement & 0xFFFFFF)
                    elif instruction.mnemonic == 'blx':
                        target_hex = int.from_bytes(self.blx_call(address - instruction.address), byteorder='little')

                    # 파일 오프셋 계산
                    file_offset = self.calculate_file_offset(instruction.address)
                    with open(self.filepath+"_mod", 'rb') as f:
                        f.seek(file_offset)
                        instruction_bytes = f.read(4)
                        file_hex = int.from_bytes(instruction_bytes, byteorder='little')

                    if target_hex == file_hex:
                        bl_instructions.append((instruction.address, instruction.mnemonic, instruction.op_str))

        return bl_instructions

    def patch_bl_instruction(self, bl_address, new_target_address, mnemonic='bl'):
        # BL 명령어의 파일 오프셋 계산
        file_offset = self.calculate_file_offset(bl_address)

        # 새로운 BL 명령어의 상대 오프셋 계산
        relative_offset = (new_target_address - bl_address - 8) // 4
        # 새로운 BL 명령어 생성
        new_bl_instruction = 0
        if mnemonic == 'bl':
            new_bl_instruction = 0xEB000000 | (relative_offset & 0xFFFFFF)
        elif mnemonic == 'b':
            new_bl_instruction = 0xEA000000 | (relative_offset & 0xFFFFFF)
        elif mnemonic == 'blx':
            new_bl_instruction = int.from_bytes(self.blx_call(new_target_address - bl_address), byteorder='little')

        # 파일 오프셋으로 이동하여 BL 명령어 수정
        with open(self.filepath+"_mod", 'r+b') as f:
            f.seek(file_offset)
            f.write(new_bl_instruction.to_bytes(4, byteorder='little'))

    def blx_call(self, size: int) -> bytearray:
        if size < 0:
            return self.blx_call_back(-size)
        if size % 4 == 2:
            size = size - 2
        size = size - 4
        size = size >> 1
        imm10 = (size & 0b111111111100000000000) >> 11
        imm11 = size & 0b11111111111
        high = (0b111100 << 10) | imm10
        low = (0b11101 << 11) | imm11

        return high.to_bytes(2, 'little') + low.to_bytes(2, 'little')

    def blx_call_back(self, size: int) -> bytearray:
        if size % 4 == 2:
            size = size + 2
        size = size + 4
        size = (size ^ 0xFFFFFFFF) + 1
        size = size >> 1
        imm10 = (size & 0b111111111100000000000) >> 11
        imm11 = size & 0b11111111111
        high = (0b111101 << 10) | imm10
        low = (0b11101 << 11) | imm11

        return high.to_bytes(2, 'little') + low.to_bytes(2, 'little')