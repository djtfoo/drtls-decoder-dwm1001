def octets_to_binary(hex, num_octets, endianness):
    base = 16  # hexadecimal
    #num_of_bits = num_octets * 8
    #return bin(int(fc, base))[2:].zfill(num_of_bits)

    bin_str = ""
    # NOTE: 'endianness' isn't the best term to use here
    if endianness == "little":
        for i in reversed(range(num_octets)):
            bin_str += octet_to_binary(hex[i*2:(i+1)*2]) #, endianness)
    else: # endianness == "big":
        for i in range(num_octets):
            bin_str += octet_to_binary(hex[i*2:(i+1)*2]) #, endianness)
        
    return bin_str

def binary_to_octets():
    pass

def octet_to_binary(hex): #, endianness):
    base = 16  # hexadecimal
    num_of_bits = 8
    return bin(int(hex, base))[2:].zfill(num_of_bits)
    
def slice_bits(bin_str, start, stop, num_bits, flip_bit_idx=False):
    if flip_bit_idx: # bit [0] is at [len-1]
        idx_start = num_bits - start
        idx_stop = num_bits - stop - 1
        return bin_str[idx_stop:idx_start]
    else:  # start and stop inclusive
        return bin_str[start:stop+1]

def slice_octets(hex_str, start, num_octets, endianness="big"):
    # one octet is 2 hex characters
    if endianness == "big":
        start_idx = start*2
        stop_idx = start_idx + num_octets*2
        return hex_str[start_idx:stop_idx]
    elif endianness == "little":
        sliced = ""
        for i in reversed(range(num_octets)):
            sliced += hex_str[(start+i)*2 : (start+i+1)*2]
        return sliced
    else:
        raise NotImplementedError()

class Bits:
    def __init__(self, bits):
        self.data = bits
        self.length = len(bits)

    def to_string(self):
        return "{0}'b{1}".format(self.length, self.data)

class BitFlag:
    def __init__(self, bit, name):
        self.data = Bits(bit)
        self.name = name
        self.value = False if (bit == "0") else True

    def get_data(self):
        return self.value

    def to_string(self):
        return "{0}: {1} ({2})".format(self.name, self.value, self.data.to_string())

class OctetData:
    def __init__(self, octets, name, is_bits, endianness="little"):
        self.data = octets
        self.length = len(octets) // 2  # no. octets
        self.name = name
        self.isBits = is_bits
        if is_bits:
            # NOTE: 'endianness' here might overlap with the typical input for octets, which is slice_octets
            self.bin = Bits(octets_to_binary(octets, self.length, endianness))

    def get_data(self):
        return self.data.to_string()

    def to_string(self):
        to_str = "{0}: 0x{1}".format(self.name, self.data)
        if self.isBits:
            to_str += " ({})".format(self.bin.to_string())
        return to_str
