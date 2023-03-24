import pefile

# Open the PE file
pe = pefile.PE("file.exe")#put in same directory

# Iterate over the data directories to find the embedded executable
for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if entry.name is not None and b"RT_RCDATA" in entry.name:
        # Get the embedded executable data
        data_rva = entry.directory.entries[0].data.struct.OffsetToData
        size = entry.directory.entries[0].data.struct.Size
        data = pe.get_memory_mapped_image()[data_rva:data_rva+size]

        # Write the embedded executable to a new file
        with open("extracted.exe", "wb") as f:
            f.write(data)
