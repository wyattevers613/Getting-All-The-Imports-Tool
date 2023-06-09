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

                # Find the two push instructions that load the function name and module handle
                push_instructions = []
                for push_instruction in reversed(list(cs.disasm(text_section.get_data()[:instruction.address - text_section.VirtualAddress], text_section.VirtualAddress))):
                    if push_instruction.mnemonic == "push":
                        push_instructions.append(push_instruction)
                        if len(push_instructions) == 2:
                            break

                if len(push_instructions) == 2:
                    # Check if the second push instruction contains a valid hex address
                    hex_value_match = re.search(r'0x[0-9a-fA-F]+', push_instructions[1].op_str)

                    if hex_value_match:
                        # Convert the hex address to an integer
                        module_handle_address = int(hex_value_match.group(0), 16)

                        # Read the little-endian address from the data section
                        module_handle_le = pe.get_data(module_handle_address - pe.OPTIONAL_HEADER.ImageBase, 4)
                        module_handle = int.from_bytes(module_handle_le, byteorder='little', signed=False)

                        # Check if the first push instruction loads a register value
                        if push_instructions[0].op_str.lower() in ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi']:
                            # Use the register value as the function address
                            register_name = push_instructions[0].op_str.lower()
                            register_value = getattr(cs.registers, register_name)
                            function_address = register_value
                        else:
                            # Read the function name from the first push instruction
                            function_name_address = int(push_instructions[0].op_str, 16)
                            function_name = pe.get_string_at_rva(function_name_address - pe.OPTIONAL_HEADER.ImageBase)

                            # Get the function address using GetProcAddress
                            function_address = pe.getProcAddress(module_handle, function_name.decode())

                        # Add the function name to the list of loaded functions and print it
                        loaded_functions.append(function_name.decode())
                        print(f"  Loading function: {function_name}")
                    else:
                        print(f"  Cannot resolve function name from instruction: {push_instructions[1].mnemonic} {push_instructions[1].op_str}")

    print("\nLate Loaded libraries:")
    for library in loaded_libraries:
        print(library)

    print("\nLate Loaded functions:")
    for function in loaded_functions:
        print(function)

if __name__ == "__main__":
    find_loadlibrarya_getprocaddress_calls(file_path)

