from helper import octets_to_binary, slice_bits, slice_octets, Bits, BitFlag, OctetData

import message_payload as mp

class FrameType:
    def __init__(self, bits):
        self.data = Bits(bits)
        # decode Frame Type
        self.frameType = self.decode_frame_type(bits)

    def get_data(self):
        return self.frameType

    def to_string(self):
        return "Frame Type: {0} ({1})".format(self.frameType, self.data.to_string())

    def decode_frame_type(self, bits):
        # FC bits 2 to 0
        if bits == "000":
            return "Beacon"
        elif bits == "001":
            return "Data"
        elif bits == "010":
            return "Acknowledgement"
        elif bits == "011":
            return "MAC Command"
        else:
            return "Reserved"

class AddressMode:
    NO_ADDR_OR_PANID = "No address or PAN ID present"
    RESERVED = "Reserved"
    SHORT_ADDR = "Short (16-bit) address"
    LONG_ADDR = "Extended (64-bit) address"

    def __init__(self, bits):
        self.data = Bits(bits)
        # decode Address Mode
        self.addrMode = self.decode_addr_mode(bits)

    def get_data(self):
        return self.addrMode

    def decode_addr_mode(self, bits):
        # FC bits 11 & 10 (dest) or 15 & 14 (src)
        if bits == "00":
            return self.NO_ADDR_OR_PANID
        elif bits == "01":
            return self.RESERVED
        elif bits == "10":
            return self.SHORT_ADDR
        elif bits == "11":
            return self.LONG_ADDR

    def to_string(self):
        return "Address Mode: {0} ({1})".format(self.addrMode, self.data.to_string())

class FrameControl:
    def __init__(self, hex_fc):
        self.data = OctetData(hex_fc, "Frame Control (FC)", True)
        # decode FC - bit 0 refers to LSB, data (bytes) is in Little endian format
        bits = octets_to_binary(hex_fc, 2, "little")
        self.frameType = FrameType(slice_bits(bits, 0, 2, 16, True))
        self.securityEnabled = BitFlag(slice_bits(bits, 3, 3, 16, True), "Security Enabled")
        self.framePending = BitFlag(slice_bits(bits, 4, 4, 16, True), "Frame Pending")
        self.ACKRequest = BitFlag(slice_bits(bits, 5, 5, 16, True), "ACK Request")
        self.PANIDCompress = BitFlag(slice_bits(bits, 6, 6, 16, True), "PAN ID Compress")
        self.destAddrMode = AddressMode(slice_bits(bits, 10, 11, 16, True))
        self.frameVersion = OctetData(slice_bits(bits, 12, 13, 16, True), "Frame Version", False)
        self.srcAddrMode = AddressMode(slice_bits(bits, 14, 15, 16, True))

    def to_string(self):
        return self.data.to_string()  # Frame Control (FC) data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # FC metadata
        data_str += start_spacing + self.data.to_string() + " - "  # FC
        data_str += "Length: " + str(self.data.length) + "\n"  # FC Length
        # FC contents
        data_str += indented + self.frameType.to_string() + "\n"  # Frame Type
        data_str += indented + self.securityEnabled.to_string() + "\n"  # Security enabled
        data_str += indented + self.framePending.to_string() + "\n"  # Frame Pending
        data_str += indented + self.ACKRequest.to_string() + "\n"  # ACK Request
        data_str += indented + self.PANIDCompress.to_string() + "\n"  # PAN ID Compress
        data_str += indented + "Destination " + self.destAddrMode.to_string() + "\n"  # Destination address mode
        data_str += indented + self.frameVersion.to_string() + "\n"  # Frame version
        data_str += indented + "Source " + self.srcAddrMode.to_string()  # Source address mode
        # return data
        return data_str


class MACHeader:
    def __init__(self, data):  # pass in entire frame data, as non-DWM1001 frames could be a variable length
        # Decode Frame Control (FC) first to determine MAC Header length and parameters
        self.frameControl = FrameControl(slice_octets(data, 0, 2))  # first 2 bytes
        self.sequenceNumber = OctetData(slice_octets(data, 2, 1), "Sequence Number", False)

        # depending on decoded FC, process the following header data
        # Destination PANID and Address
        if self.frameControl.destAddrMode.addrMode != AddressMode.NO_ADDR_OR_PANID and self.frameControl.destAddrMode.addrMode != AddressMode.RESERVED:  # there is a destination address
            self.destPANID = OctetData(slice_octets(data, 3, 2, endianness="little"), "Destination PAN ID", False)
            if self.frameControl.destAddrMode.addrMode == AddressMode.SHORT_ADDR:
                self.destAddr = OctetData(slice_octets(data, 5, 2, endianness="little"), "Destination Address", False)
                srcPANID_idx = 7
            else:  #elif self.frameControl.destAddrMode.addrMode == AddressMode.LONG_ADDR:
                self.destAddr = OctetData(slice_octets(data, 5, 8, endianness="little"), "Destination Address", False)            
                srcPANID_idx = 13
        else:
            self.destPANID = None
            self.destAddr = None
            srcPANID_idx = 3
        
        # Source PANID and Address
        if self.frameControl.srcAddrMode.addrMode != AddressMode.NO_ADDR_OR_PANID and self.frameControl.srcAddrMode.addrMode != AddressMode.RESERVED:  # there is a source address
            if not self.frameControl.PANIDCompress.value:  # DWM1001 compresses PAN ID
                self.srcPANID = OctetData(slice_octets(data, srcPANID_idx, 2, endianness="little"), "Source PAN ID", False)
                srcAddr_idx = srcPANID_idx + 2
            else:
                self.srcPANID = None
                srcAddr_idx = srcPANID_idx
            if self.frameControl.srcAddrMode.addrMode == AddressMode.SHORT_ADDR:
                self.srcAddr = OctetData(slice_octets(data, srcAddr_idx, 2, endianness="little"), "Source Address", False)
                auxSecurityHeader_idx = srcAddr_idx + 2
            else:  #elif self.frameControl.srcAddrMode.addrMode == AddressMode.LONG_ADDR:
                self.srcAddr = OctetData(slice_octets(data, srcAddr_idx, 8, endianness="little"), "Source Address", False)
                auxSecurityHeader_idx = srcAddr_idx + 8
        else:
            self.srcPANID = None
            self.srcAddr = None
            auxSecurityHeader_idx = srcPANID_idx

        # Aux Security Header
        #if not self.frameControl.securityEnabled:  # DWM1001 does not have this, so it is always False
        self.auxSecurityHeader = None
        # auxSecurityHeader_idx = length of MAC header

        # Store the total header as data
        self.data = OctetData(slice_octets(data, 0, auxSecurityHeader_idx), "MAC Header", False)

    def get_length(self):
        return self.data.length

    def to_string(self):
        return self.data.to_string()  # MAC Header data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Header metadata
        data_str += start_spacing + self.data.to_string() + " - "  # MAC Header
        data_str += "Length: " + str(self.get_length()) + "\n"  # MAC Header Length
        data_str += self.frameControl.data_breakdown(num_spaces+1) + "\n"  # FC breakdown
        #data_str += "\n"
        # Header contents
        data_str += indented + self.sequenceNumber.to_string() + "\n"  # Sequence Number
        if self.destPANID != None:
            data_str += indented + self.destPANID.to_string() + "\n"  # Destination PANID
        if self.destAddr != None:
            data_str += indented + self.destAddr.to_string() + "\n"  # Destination Address
        if self.srcPANID != None:
            data_str += indented + self.srcPANID.to_string() + "\n"  # Source PANID (DWM1001 does not have this)
        if self.srcAddr != None:
            data_str += indented + self.srcAddr.to_string() + "\n"  # Source Address
        if self.auxSecurityHeader != None:
            data_str += indented + self.auxSecurityHeader.to_string() + "\n"  # Aux Security Header (DWM1001 does not have this)
        # return data
        return data_str


class FrameData:
    def __init__(self, data):
        # store the data
        self.data = OctetData(data, "UWB Frame Data", False)
        # 1. Decode MAC header
        self.macHeader = MACHeader(data)
        # 2. Decode message payload
        start = self.macHeader.get_length()*2
        stop = len(data) - 4  # excluding last 2 bytes
        self.payload = mp.MessagePayload(data[start : stop])  # rest of the data, excluding FCS
        # 3. Extract FCS (last 2 bytes)
        self.fcs = OctetData(data[stop:], "Frame Check Sequence (FCS)", False)

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Frame metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Frame Data
        data_str += "Length: " + str(self.data.length) + "\n"    # Frame Data length
        # Message contents
        data_str += self.macHeader.data_breakdown(num_spaces+1)  # MAC Header
        data_str += self.payload.data_breakdown(num_spaces+1)    # Payload
        data_str += indented + self.fcs.to_string()     # FCS
        # return data
        return data_str