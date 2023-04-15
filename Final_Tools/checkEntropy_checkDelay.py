import math
import re

#######Checks Signs of Entropy########
def checkEntropy(path):
    with open(path,'rb') as f:
        data = f.read()
    entropy = sum((data.count(chr(i)) / float(len(data))) * \
        math.log((data.count(chr(i)) / float(len(data))) , 2) for i in range(256))
    if entropy > 7:
        return True
    else:
        False

def checkDelay(path):
    # Open the file and read in the contents
    with open(path, "rb") as f:
        data = f.read()

    # Find all printable ASCII strings in the data
    strings = re.findall(br"[ -~]{6,}", data)

    # Check each string for the substring "dwMilliseconds"
    for string in strings:
        if b"dwMilliseconds" or 'Sleep' in string:
            return True
    return False