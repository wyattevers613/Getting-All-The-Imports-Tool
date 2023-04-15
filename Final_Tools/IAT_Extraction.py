import pefile

# specify the path of the executable


def extract(path):
    # grab existing IAT

    # load the executable into pefile
    pe = pefile.PE(path)

    # get the Import Address Table
    iat = pe.DIRECTORY_ENTRY_IMPORT

    libraries_count = 0
    function_count = 0

    # print out the IAT
    print("Import Address Table:")
    for entry in iat:
        libraries_count += 1
        print("    " + entry.dll.decode())
        
        for imp in entry.imports:
            function_count += 1
            print("        " + hex(imp.address) + " " + imp.name.decode())
        
    print("\n")
    print(f"Total Libraries Imported: {libraries_count}")
    print(f"Total Functions Imported: {function_count}")

