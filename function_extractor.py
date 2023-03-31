import pefile
import capstone
import re

file_path = "C:\\Users\\user\\Desktop\\Project\\meoware.exe"

def find_getprocaddress_calls(file_path):
    pe = pefile.PE(file_path)

    for section in pe.sections:
        if b".text" in section.Name:
            text_section = section
            break
    else:
        print("No .text section found.")
        return

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    getprocaddress_address = None
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll.lower() == b"kernel32.dll":
            for imp in entry.imports:
                if imp.name and imp.name.decode().lower() == "getprocaddress":
                    getprocaddress_address = imp.address
                    break
            if getprocaddress_address:
                break
    if not getprocaddress_address:
        print("GetProcAddress not found in import table.")
        return

    disassembly = cs.disasm(text_section.get_data(), text_section.VirtualAddress)

    loaded_functions = []

    for instruction in disassembly:
        if instruction.mnemonic == "call":
            hex_number = re.search(r'0x[0-9a-fA-F]+', instruction.op_str)
            if hex_number and int(hex_number.group(0), 16) == getprocaddress_address:
                print(f"GetProcAddress call found at: 0x{instruction.address:x}")

                push_instructions = []
                for push_instruction in reversed(list(cs.disasm(text_section.get_data()[:instruction.address - text_section.VirtualAddress], text_section.VirtualAddress))):
                    if push_instruction.mnemonic == "push":
                        push_instructions.append(push_instruction)
                        if len(push_instructions) == 2:
                            break

                if len(push_instructions) == 2:
                    if re.match(r'0x[0-9a-fA-F]+', push_instructions[0].op_str):
                        function_name_address = int(push_instructions[0].op_str, 16)
                        function_name = pe.get_string_at_rva(function_name_address - pe.OPTIONAL_HEADER.ImageBase)
                        loaded_functions.append(function_name.decode())
                        print(f"  Loading function: {function_name}")
                    else:
                        print(f"  Cannot resolve function name from register {push_instructions[0].op_str}")

    print("\nLoaded functions:")
    for function in loaded_functions:
        print(function)

if __name__ == "__main__":
    import sys

    # if len(sys.argv) < 2:
    #     print("Usage: python find_getprocaddress.py <path_to_exe_file>")
    #     sys.exit(1)

    # exe_file_path = sys.argv[1]
    find_getprocaddress_calls(file_path)
