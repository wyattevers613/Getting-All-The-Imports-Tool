# ChatGPT Generated

#######Extracts Embedded Executable File######
import pefile
import math
import re

def extract():
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

#######Checks Signs of Entropy########
def checkEntropy():
    with open("file_path",'rb') as f:
        data = f.read()
    entropy = sum((data.count(chr(i)) / float(len(data))) * \
        math.log((data.count(chr(i)) / float(len(data))) , 2) for i in range(256))
    if entropy > 7:
        return True
    else:
        False

def checkDelay():
    # Open the file and read in the contents
    with open("path/to/file", "rb") as f:
        data = f.read()

    # Find all printable ASCII strings in the data
    strings = re.findall(br"[ -~]{6,}", data)

    # Check each string for the substring "dwMilliseconds"
    for string in strings:
        if b"dwMilliseconds" or 'Sleep' in string:
            return True
    return False