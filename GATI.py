import sys
import os
from Final_Tools.checkEntropy_checkDelay import checkEntropy, checkDelay
from Final_Tools.IAT_Extraction import extract as iat_extract
from Final_Tools.DelayLoadExtractor import find_loadlibrarya_getprocaddress_calls

# complete all command line parsing and error checking
if len(sys.argv) != 2:
    print("Usage: python GATI.py <path-to-executable>")
    sys.exit(1)

file_path = sys.argv[1]

if not os.path.isfile(file_path):
    print(f"Error: File '{file_path}' does not exist.")
    sys.exit(1)

# print a welcome message to the GATI tool
print("\n")
print("Welcome to the GATI tool!")
print("\n")

# Embedded and UPX unpacking
# print out formatted results
# 
# print("\n")

# Entropy / Delay
# # run check entropy with checkEntropy(path) and print out result
# entropy_result = checkEntropy(file_path)
# print(f"Entropy result: {entropy_result}")
# print("\n")
# # run checkDelay(path) and print out result
# delay_result = checkDelay(file_path)
# print(f"Delay check result: {delay_result}")
# print("\n")

# run IAT_Extraction.extract(path), it will print out results on its own
print("Visible Import Address Table...")
print("\n")
iat_extract(file_path)
print("\n")
print("Hidden Libraries and Functions...")
# run the delay load checker and print out results
libraries, functions = find_loadlibrarya_getprocaddress_calls(file_path)
print("\n")
print("Delay-loaded libraries:")
for library in libraries:
    print(f"  {library}")
print("\n")
print("\nDelay-loaded functions:")
for library, function in functions:
    print(f"  {library}: {function}")
