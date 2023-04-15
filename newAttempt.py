import pefile
import capstone
import re

file_path = "C:\\Users\\user\\Desktop\\Project\\meoware.exe"

def find_delay_loaded_functions(file_path):
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

    # Find the library and function names in the .data section
    lib_names = {}
    func_names = {}
    for section in pe.sections:
        if section.Name.decode().startswith(".data"):
            data = section.get_data()
            for m in re.finditer(rb"(.+)\x00(.+)\x00", data):
                lib_name, func_name = m.groups()
                lib_names[lib_name] = section.VirtualAddress + m.start(1)
                func_names[func_name] = section.VirtualAddress + m.start(2)

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
                        library_name_address = library_address - pe.OPTIONAL_HEADER.ImageBase + lib_names.get(pe.get_data(library_address - pe.OPTIONAL_HEADER.ImageBase, 100).split(b'\0')[0])
                        library_name = pe.get_string_at_rva
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
                    # Check if the second push instruction contains a valid hex address
                    hex_value_match = re.search(r'0x[0-9a-fA-F]+', push_instructions[1].op_str)

                    if hex_value_match:
                        # Convert the hex address to an integer
                        data_address = int(hex_value_match.group(0), 16)

                        # Read the little-endian address from the data section
                        function_name_address_le = pe.get_data(data_address - pe.OPTIONAL_HEADER.ImageBase, len("WelcomeMessage") + 1)
                        function_name_address = function_name_address_le.split(b'\0')[0]
                        function_name_address = function_name_address - pe.OPTIONAL_HEADER.ImageBase + func_names.get(function_name_address_le.split(b'\0')[1])

                        # Get the function name from the address in the PE file
                        function_name = pe.get_string_at_rva(function_name_address)

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
    find_delay_loaded_functions(file_path)

