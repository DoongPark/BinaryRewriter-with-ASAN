from binaryrewriter.reassembler import Reassembler
from keystone import *

class Trampoline(Reassembler):
    def __init__(self, filepath):
        super().__init__(filepath)

    def assemble_arm_code(self, assembly_code):
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        encoding, _ = ks.asm(assembly_code)
        print("Machine Code:", repr(bytes(encoding)))

        return encoding

    def register_push(self, address):
        # 함수 실행 전에 스택에 저장할 레지스터
        assembly_push = "stm sp!, {R0-R12, lr}"
        push_code = self.assemble_arm_code(assembly_push)

        file_offset = self.calculate_file_offset(address)
        with open(self.filepath + "_mod", 'r+b') as f:
            f.seek(file_offset)
            f.write(push_code)

    def register_pop(self, address):
        # 함수 실행 후에 스택에서 복구할 레지스터
        assembly_pop = "ldm sp!, {R0-R12, pc}"
        pop_code = self.assemble_arm_code(assembly_pop)

        file_offset = self.calculate_file_offset(address)
        with open(self.filepath + "_mod", 'r+b') as f:
            f.seek(file_offset)
            f.write(pop_code)