import pefile
import capstone
import re

file_path = "C:\\Users\\user\\Desktop\\Project\\meoware.exe"

def find_loadlibrarya_getprocaddress_calls(file_path):
    # Load the PE (Portable Executable) file
    pe = pefile.PE(file_path)

    # Find the .text section in the PE file
    for section in pe.sections:
        if b".text" in section.Name:
            text_section = section
            break
    else:
        print("No .text section found.")
        return

    # Initialize the Capstone disassembler for x86 32-bit
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    # Find the addresses of LoadLibraryA and GetProcAddress in the import table
    loadlibrarya_address = None
    getprocaddress_address = None
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll.lower() == b"kernel32.dll":
            for imp in entry.imports:
                imp_name = imp.name.decode().lower() if imp.name else ''
                if imp_name == "loadlibrarya":
                    loadlibrarya_address = imp.address
                elif imp_name == "getprocaddress":
                    getprocaddress_address = imp.address

                if loadlibrarya_address and getprocaddress_address:
                    break
            if loadlibrarya_address and getprocaddress_address:
                break

    if not loadlibrarya_address:
        print("LoadLibraryA not found in import table.")
        return

    if not getprocaddress_address:
        print("GetProcAddress not found in import table.")
        return

    # Disassemble the .text section
    disassembly = cs.disasm(text_section.get_data(), text_section.VirtualAddress)

    # Initialize lists to store loaded libraries and functions
    loaded_libraries = []
    loaded_functions = []

    # Iterate through the disassembled instructions
    for instruction in disassembly:
        hex_value_match = re.search(r'0x[0-9a-fA-F]+', instruction.op_str)
        if instruction.mnemonic == "call" and hex_value_match:
            call_address = int(hex_value_match.group(0), 16)

            # Check for LoadLibraryA calls
            if call_address == loadlibrarya_address:
                print(f"LoadLibraryA call found at: 0x{instruction.address:x}")

                # Find the push instruction that loads the library name
                for push_instruction in reversed(list(cs.disasm(text_section.get_data()[:instruction.address - text_section.VirtualAddress], text_section.VirtualAddress))):
                    if push_instruction.mnemonic == "push":
                        library_address = int(push_instruction.op_str, 16)
                        library_name = pe.get_string_at_rva(library_address - pe.OPTIONAL_HEADER.ImageBase)
                        loaded_libraries.append(library_name.decode())
                        print(f"  Loading library: {library_name}")
                        break

            # Check for GetProcAddress calls
            elif call_address == getprocaddress_address:
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
                        # If the function name is loaded into a register, try to find the push instruction that loads the address into the register
                        register = push_instructions[0].op_str
                        for push_instruction in reversed(list(cs.disasm(text_section.get_data()[:push_instructions[1].address - text_section.VirtualAddress], text_section.VirtualAddress))):
                            if push_instruction.mnemonic == "push" and push_instruction.op_str == register:
                                if re.match(r'0x[0-9a-fA-F]+', push_instruction.op_str):
                                    function_name_address = int(push_instruction.op_str, 16)
                                    function_name = pe.get_string_at_rva(function_name_address - pe.OPTIONAL_HEADER.ImageBase)
                                    loaded_functions.append(function_name.decode())
                                    print(f"  Loading function: {function_name}")
                                break
                        else:
                            print(f"  Cannot resolve function name from register {register}")

    print("\nLoaded libraries:")
    for library in loaded_libraries:
        print(library)

    print("\nLoaded functions:")
    for function in loaded_functions:
        print(function)

if __name__ == "__main__":
    find_loadlibrarya_getprocaddress_calls(file_path)


