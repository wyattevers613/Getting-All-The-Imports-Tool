import pefile
import os
import struct
import hashlib

####### THE BELOW CODE WAS PARTIALLY WRITTEN BY CHAT GPT. I WOULD ASK IT TO WRITE MY PYTHON CODE TO CALCULATE THE IMPHASH OF THE FILE AND WOULD
####### HAVE TO FIT IT INTO THE PARAMETERS OF THE REST OF MY CODE.
def calculate_imphash(file_path):
    file = open(file_path, 'rb')
    imphash = hashlib.md5(file.read()).hexdigest()
    file.close()
    return imphash

def PE_Extractor(file_path):

    data = open("pe_file_1.bin", 'rb').read()
    offset = 0
    counter = 0
    while True:
        offset = data.find(b'MZ', offset)

        if offset == -1:
            break
        header = data[offset:offset+2]

        if header == b'MZ':
            pe_offset = struct.unpack('<I', data[offset+0x3C:offset+0x40])[0]
            pe_data = data[offset+pe_offset:]
            
            with open('MZ_file_{:x}.bin'.format(offset), 'wb+') as f:
                f.write(pe_data)

        offset += 1
        counter += 1 
    print("Found {} PE files".format(counter))

# Detects if the file is UPX packed
def isUPXpacked(file):
    try:
        with open(file, "rb") as fp:
            return fp.read(3).decode('utf-8', errors='ignore')
    except Exception as e:
        print(e)
        return False

def unpackUPX(file):
    
    if isUPXpacked(file):
        os.system('cp ' + file + ' C:/Users/user/Alex/pe_file_1.bin')
        file = "C:\\Users\\user\\Alex\\pe_file_1.bin"
        os.system('upx -d ' + file)

    PE_Extractor(file)

#Eventually want the user to type in the malware they want to investigate    
file = "C:\\Users\\user\\Alex\\meoware_packed.exe"

unpackUPX(file)

for file in os.listdir():
    # Check if the file starts with "MZ"
    if file.startswith('MZ'):
        #send the file through the function
        imphash = calculate_imphash("C:\\Users\\user\\Alex\\"+file)
        print("Your imphash value for " + file + " is " + imphash)


######### ABOVE IS ALL CHAT GPT GENERATED ##########
