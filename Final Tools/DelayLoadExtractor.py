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

    loadlibrarya_address, getprocaddress_address = None, None
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

    disassembly = cs.disasm(text_section.get_data(), text_section.VirtualAddress)

    loaded_libraries = []
    loaded_functions = []
    loadlibrarya_calls = []

    for instruction in disassembly:
        hex_value_match = re.search(r'0x[0-9a-fA-F]+', instruction.op_str)
        if instruction.mnemonic == "call" and hex_value_match:
            call_address = int(hex_value_match.group(0), 16)

            if call_address == loadlibrarya_address:
                loadlibrarya_calls.append(instruction.address)
                for push_instruction in reversed(list(cs.disasm(text_section.get_data()[:instruction.address - text_section.VirtualAddress], text_section.VirtualAddress))):
                    if push_instruction.mnemonic == "push":
                        library_address = int(push_instruction.op_str, 16)
                        library_name = pe.get_string_at_rva(library_address - pe.OPTIONAL_HEADER.ImageBase)
                        loaded_libraries.append(library_name.decode())
                        break

            elif call_address == getprocaddress_address:
                loaded_library = None
                for loadlibrarya_call in reversed(loadlibrarya_calls):
                    if loadlibrarya_call < instruction.address:
                        loaded_library = loaded_libraries[loadlibrarya_calls.index(loadlibrarya_call)]
                        break

                if loaded_library:
                    for push_instruction in reversed(list(cs.disasm(text_section.get_data()[:instruction.address - text_section.VirtualAddress], text_section.VirtualAddress))):
                        if push_instruction.mnemonic == "push" and push_instruction != instruction:
                            if re.match(r'^0x[0-9a-fA-F]+$', push_instruction.op_str):
                                function_address = int(push_instruction.op_str, 16)
                            else:
                                continue
                            function_name = pe.get_string_at_rva(function_address - pe.OPTIONAL_HEADER.ImageBase)
                            loaded_functions.append((loaded_library, function_name.decode()))
                            break

    return loaded_libraries, loaded_functions


libraries, functions = find_loadlibrarya_getprocaddress_calls(file_path)

if __name__ == "__main__":
    libraries, functions = find_loadlibrarya_getprocaddress_calls(file_path)

    print("Delay-loaded libraries:")
    for library in libraries:
        print(f"  {library}")

    print("\nDelay-loaded functions:")
    for library, function in functions:
        print(f"  {library}: {function}")

   
