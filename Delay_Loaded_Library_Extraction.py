import pefile
import capstone

def find_loadlibrarya_calls(file_path):
    pe = pefile.PE(file_path)

    for section in pe.sections:
        if b".text" in section.Name:
            text_section = section
            break
    else:
        print("No .text section found.")
        return

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    loadlibrarya_address = None
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll.lower() == b"kernel32.dll":
            for imp in entry.imports:
                if imp.name and imp.name.decode().lower() == "loadlibrarya":
                    loadlibrarya_address = imp.address
                    break
            if loadlibrarya_address:
                break
    if not loadlibrarya_address:
        print("LoadLibraryA not found in import table.")
        return

    disassembly = cs.disasm(text_section.get_data(), text_section.VirtualAddress)

    loaded_libraries = []

    for instruction in disassembly:
        if instruction.mnemonic == "call" and int(instruction.op_str, 16) == loadlibrarya_address:
            print(f"LoadLibraryA call found at: 0x{instruction.address:x}")

            # Search for the push instruction that sets the argument for LoadLibraryA
            for push_instruction in reversed(list(cs.disasm(text_section.get_data()[:instruction.address - text_section.VirtualAddress], text_section.VirtualAddress))):
                if push_instruction.mnemonic == "push":
                    library_address = int(push_instruction.op_str, 16)
                    library_name = pe.get_string_at_rva(library_address - pe.OPTIONAL_HEADER.ImageBase)
                    loaded_libraries.append(library_name.decode())
                    print(f"  Loading library: {library_name}")
                    break

    print("\nLoaded libraries:")
    for library in loaded_libraries:
        print(library)

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python find_loadlibrarya.py <path_to_exe_file>")
        sys.exit(1)

    exe_file_path = sys.argv[1]
    find_loadlibrarya_calls(exe_file_path)
