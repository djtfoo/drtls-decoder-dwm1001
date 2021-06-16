from helper import octets_to_binary, slice_bits, slice_octets, Bits, BitFlag, OctetData

import struct

class NumData(OctetData):
    # NOTE: the endianness here refers to decoding the bits MSB or LSB first, and not how to unpack the data
    def __init__(self, octets, name, unpack_format, endianness="little"):
        super().__init__(octets, name, False, endianness)
        # compute value
        self.value = struct.unpack(unpack_format, bytes(bytearray.fromhex(octets)) )[0]
    
    # Override
    def to_string(self):
        to_str = "{0}: {1} (0x{2})".format(self.name, self.value, self.data)
        return to_str

class MsgBeacon:
    VARIABLE_LENGTH = False
    LENGTH = 23
    MSG_ID = "10"
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_BCN"
    def __init__(self, data):
        # decode payload
        self.sessionId = OctetData(slice_octets(data, 1, 1, endianness="little"), "Session ID", False)
        self.clusterFlags = OctetData(slice_octets(data, 2, 2, endianness="little"), "Cluster Flags", True, endianness="big")
        self.sfNumber = OctetData(slice_octets(data, 4, 2, endianness="little"), "Superframe Number", False)
        self.clusterSlotNumber = OctetData(slice_octets(data, 6, 1, endianness="little"), "Cluster Slot Number", False)
        self.clusterMap = OctetData(slice_octets(data, 7, 4, endianness="little"), "Cluster Map", True, endianness="big")
        self.dataSlotMap = OctetData(slice_octets(data, 11, 2, endianness="little"), "Data Slot Map", True)
        self.nonce = OctetData(slice_octets(data, 13, 10, endianness="little"), "NONCE", False)
        # store message data
        self.data = OctetData(slice_octets(data, 0, self.LENGTH, endianness="big"), "Beacon Message", False)
        self.length = self.LENGTH  # no. octets

    def to_string(self):
        return self.data.to_string()  # Beacon message data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Beacon message
        data_str += "Length: " + str(self.length) + "\n"    # Beacon message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.sessionId.to_string() + "\n"  # Session ID
        data_str += indented + self.clusterFlags.to_string() + "\n"  # Cluster Flags
        data_str += indented + self.sfNumber.to_string() + "\n"  # Superframe (SF) Number
        data_str += indented + self.clusterSlotNumber.to_string() + "\n"  # Cluster Slot Number
        data_str += indented + self.clusterMap.to_string() + "\n"  # Cluster Map
        data_str += indented + self.dataSlotMap.to_string() + "\n"  # Data Slot Map
        data_str += indented + self.nonce.to_string() + "\n"  # NONCE
        # return data
        return data_str

class MsgJoinRequest:
    VARIABLE_LENGTH = False
    LENGTH = 18
    MSG_ID = "12"
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_CL_JOIN"
    def __init__(self, data):
        # decode payload
        self.hardwareVersion = OctetData(slice_octets(data, 1, 4, endianness="little"), "Hardware Version", False)
        self.firmwareVersion = OctetData(slice_octets(data, 5, 4, endianness="little"), "Firmware Version", False)
        self.firmwareChecksum = OctetData(slice_octets(data, 9, 4, endianness="little"), "Firmware Checksum (CRC32)", False)
        self.options = OctetData(slice_octets(data, 13, 4, endianness="little"), "Options", True)
        self.clusterSeat = OctetData(slice_octets(data, 17, 1, endianness="little"), "Cluster Seat", True)
        # store message data
        self.data = OctetData(slice_octets(data, 0, self.LENGTH, endianness="big"), "Join Request Message", False)
        self.length = self.LENGTH  # no. octets

    def to_string(self):
        return self.data.to_string()  # Join request message data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Join request message
        data_str += "Length: " + str(self.length) + "\n"    # Join request message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.hardwareVersion.to_string() + "\n"  # Hardware Version
        data_str += indented + self.firmwareVersion.to_string() + "\n"  # Firmware Version
        data_str += indented + self.firmwareChecksum.to_string() + "\n" # Firmware Checksum
        data_str += indented + self.options.to_string() + "\n"  # Options (bitmap)
        data_str += indented + self.clusterSeat.to_string() + "\n"  # Cluster Seat
        # return data
        return data_str

class MsgJoinConfirmation:
    VARIABLE_LENGTH = False
    LENGTH = 5
    MSG_ID = "13"
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_CL_JOIN_CFM"
    def __init__(self, data):
        # decode payload
        self.address = OctetData(slice_octets(data, 1, 2, endianness="little"), "Address", False)   # locked address of the joining node
        self.clusterLock = OctetData(slice_octets(data, 3, 1, endianness="little"), "Cluster Lock", False)  # Lock counter (decrementing)
        self.clusterSeat = OctetData(slice_octets(data, 4, 1, endianness="little"), "Cluster Seat", False)  # Allocated seat number
        # store message data
        self.data = OctetData(slice_octets(data, 0, self.LENGTH, endianness="big"), "Join Confirmation Message", False)
        self.length = self.LENGTH  # no. octets

    def to_string(self):
        return self.data.to_string()  # Join confirmation message data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Join confirmation message
        data_str += "Length: " + str(self.length) + "\n"    # Join confirmation message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.address.to_string() + "\n"  # Address
        data_str += indented + self.clusterLock.to_string() + "\n"  # Cluster Lock
        data_str += indented + self.clusterSeat.to_string() + "\n"  # Cluster Seat
        # return data
        return data_str

# TODO: Almanac frame data does not match DWM1001 System Overview
class MsgAlmanac:
    VARIABLE_LENGTH = False
    LENGTH = 47 #48
    MSG_ID = "23"
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_ALMA"
    def __init__(self, data):
        # decode payload
        self.nonce = OctetData(slice_octets(data, 1, 10, endianness="little"), "NONCE", False)   # network NONCE
        #self.flags = OctetData(slice_octets(data, 11, 1, endianness="little"), "Flags", False)  # Special flags
        self.hardwareVersion = OctetData(slice_octets(data, 11, 4, endianness="little"), "Hardware version", False)  # Hardware version of sending node
        self.firmwareVersion = OctetData(slice_octets(data, 15, 4, endianness="little"), "Firmware version", False)  # Firmware version of sending node
        self.firmware1Size = OctetData(slice_octets(data, 19, 4, endianness="little"), "Firmware 1 Size", False)  # Firmware 1 size of sending node
        self.firmware2Size = OctetData(slice_octets(data, 23, 4, endianness="little"), "Firmware 2 Size", False)  # Firmware 2 size of sending node
        self.firmware1Checksum = OctetData(slice_octets(data, 27, 4, endianness="little"), "Firmware 1 Checksum", False)  # Firmware 1 checksum of sending node
        self.firmware2Checksum = OctetData(slice_octets(data, 31, 4, endianness="little"), "Firmware 2 Checksum", False)  # Firmware 2 checksum of sending node
        self.nodeId = OctetData(slice_octets(data, 35, 8, endianness="little"), "Node ID", False)  # Complete 64-bit address of sending node
        self.nodeOption = OctetData(slice_octets(data, 43, 4, endianness="little"), "Node Option", True)    # Bitmap indicating node capabilities
        # store message data
        self.data = OctetData(data, "Almanac Message", False)
        self.length = self.LENGTH  # no. octets

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Almanac message
        data_str += "Length: " + str(self.length) + "\n"    # Almanac message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.nonce.to_string() + "\n"
        #data_str += indented + self.flags.to_string() + "\n"
        data_str += indented + self.hardwareVersion.to_string() + "\n"
        data_str += indented + self.firmwareVersion.to_string() + "\n"
        data_str += indented + self.firmware1Size.to_string() + "\n"
        data_str += indented + self.firmware2Size.to_string() + "\n"
        data_str += indented + self.firmware1Checksum.to_string() + "\n"
        data_str += indented + self.firmware2Checksum.to_string() + "\n"
        data_str += indented + self.nodeId.to_string() + "\n"
        data_str += indented + self.nodeOption.to_string() + "\n"
        # return data
        return data_str

class MsgService:
    VARIABLE_LENGTH = True
    MAX_LENGTH = 17
    HEADER_LENGTH = 3
    MSG_ID = "23"
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_SVC"
    def __init__(self, data):
        # decode payload
        self.code = OctetData(slice_octets(data, 1, 1, endianness="little"), "Code", False)
        self.argc = NumData(slice_octets(data, 2, 1, endianness="little"), "No. argument octets", unpack_format='b')
        self.argv = OctetData(slice_octets(data, 3, self.argc.value, endianness="little"), "Arguments", False)
        # store message data
        self.length = self.argc.value + self.HEADER_LENGTH
        self.data = OctetData(slice_octets(data, 0, self.length, endianness="big"), "Service Message", False)

    def to_string(self):
        return self.data.to_string()  # Response message data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Service message
        data_str += "Length: " + str(self.length) + "\n"    # Service message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.code.to_string() + "\n"
        data_str += indented + self.argc.to_string() + "\n"
        data_str += indented + self.argv.to_string() + "\n"
        # return data
        return data_str

class MsgFwUpdateRequest:
    VARIABLE_LENGTH = False
    LENGTH = 24
    MSG_ID = "21"
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_FWUP_DATA_REQ"
    def __init__(self, data):
        # decode payload
        self.flags = OctetData(slice_octets(data, 1, 1, endianness="little"), "Flags", False)
        # TODO: verify update period decoding
        self.updatePeriod = NumData(slice_octets(data, 2, 2), "Update period (ms)", '<h', endianness="little")
        self.addr16_0 = OctetData(slice_octets(data, 4, 2, endianness="little"), "Addr16 0", False)
        self.addr16_1 = OctetData(slice_octets(data, 6, 2, endianness="little"), "Addr16 1", False)
        self.addr16_2 = OctetData(slice_octets(data, 8, 2, endianness="little"), "Addr16 2", False)
        self.addr16_3 = OctetData(slice_octets(data, 10, 2, endianness="little"), "Addr16 3", False)
        self.offset = OctetData(slice_octets(data, 12, 4, endianness="little"), "Offset", False)
        self.firmwareSize = OctetData(slice_octets(data, 16, 4, endianness="little"), "Firmware Size", False)
        self.firmwareChecksum = OctetData(slice_octets(data, 20, 4, endianness="little"), "Firmware Checksum", False)
        # store message data
        self.data = OctetData(slice_octets(data, 0, self.LENGTH, endianness="big"), "Firmware Update Data Request Message", False)
        self.length = self.LENGTH  # no. octets

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Beacon message
        data_str += "Length: " + str(self.length) + "\n"    # Beacon message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.flags.to_string() + "\n"
        data_str += indented + self.updatePeriod.to_string() + "\n"
        data_str += indented + self.addr16_0.to_string() + "\n"
        data_str += indented + self.addr16_1.to_string() + "\n"
        data_str += indented + self.addr16_2.to_string() + "\n"
        data_str += indented + self.addr16_3.to_string() + "\n"
        data_str += indented + self.offset.to_string() + "\n"
        data_str += indented + self.firmwareSize.to_string() + "\n"
        data_str += indented + self.firmwareChecksum.to_string() + "\n"
        # return data
        return data_str

class MsgFwUpdateData:
    VARIABLE_LENGTH = True
    MAX_LENGTH = 52
    HEADER_LENGTH = 8
    MSG_ID = "22"
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_FWUP_DATA"
    def __init__(self, data):
        # decode payload
        self.flags = OctetData(slice_octets(data, 1, 1, endianness="little"), "Flags", False)
        self.slotDataMap = OctetData(slice_octets(data, 2, 2, endianness="little"), "Slot Data Map", False)
        self.offset = OctetData(slice_octets(data, 4, 3, endianness="little"), "Offset", False)
        self.dataLength = NumData(slice_octets(data, 7, 1, endianness="little"), "Length", unpack_format='b')
        self.buffer = OctetData(slice_octets(data, 8, self.dataLength.value, endianness="little"), "Buffer", False)
        # store message data
        self.length = self.dataLength.value + self.HEADER_LENGTH
        self.data = OctetData(slice_octets(data, 0, self.length, endianness="big"), "Firmware Update Data Message", False)

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Beacon message
        data_str += "Length: " + str(self.length) + "\n"    # Beacon message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.flags.to_string() + "\n"
        data_str += indented + self.slotDataMap.to_string() + "\n"
        data_str += indented + self.offset.to_string() + "\n"
        data_str += indented + self.dataLength.to_string() + "\n"
        data_str += indented + self.buffer.to_string() + "\n"
        # return data
        return data_str

class MsgPosition:
    VARIABLE_LENGTH = False
    LENGTH = 17
    MSG_ID = "18"
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_POS"
    def __init__(self, data):
        # decode payload
        self.x = NumData(slice_octets(data, 1, 4), "X coordinate (m)", '<f', endianness="little")
        self.y = NumData(slice_octets(data, 5, 4), "Y coordinate (m)", '<f', endianness="little")
        self.z = NumData(slice_octets(data, 9, 4), "Z coordinate (m)", '<f', endianness="little")
        self.padding = OctetData(slice_octets(data, 13, 4, endianness="little"), "Padding", False)
        # store message data
        self.data = OctetData(slice_octets(data, 0, self.LENGTH, endianness="big"), "Position Message", False)
        self.length = self.LENGTH  # no. octets

    def to_string(self):
        return self.data.to_string()  # Position message data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Beacon message
        data_str += "Length: " + str(self.length) + "\n"    # Beacon message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.x.to_string() + "\n"  # X Coordinate
        data_str += indented + self.y.to_string() + "\n"  # Y Coordinate
        data_str += indented + self.z.to_string() + "\n"  # Z Coordinate
        data_str += indented + self.padding.to_string() + "\n"  # Padding
        # return data
        return data_str


class MsgGroupPoll:
    VARIABLE_LENGTH = False
    LENGTH = 29
    MSG_ID = "30"
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_TWR_GRP_POLL"
    def __init__(self, data):
        # decode payload
        self.flags = OctetData(slice_octets(data, 1, 2, endianness="little"), "Flags", True)
        self.updatePeriod = NumData(slice_octets(data, 3, 2), "Update Period", '<h', endianness="little")
        self.address0 = OctetData(slice_octets(data, 5, 2, endianness="little"), "Address (Anchor 0)", False)
        self.address1 = OctetData(slice_octets(data, 7, 2, endianness="little"), "Address (Anchor 1)", False)
        self.address2 = OctetData(slice_octets(data, 9, 2, endianness="little"), "Address (Anchor 2)", False)
        self.address3 = OctetData(slice_octets(data, 11, 2, endianness="little"), "Address (Anchor 3)", False)
        self.sequenceNumber = OctetData(slice_octets(data, 13, 1, endianness="little"), "TWR Sequence Number", False)
        # TODO: verify bit sequence for startionary flag and quality factor
        octet_statflag_qfactor = slice_octets(data, 14, 1, endianness="little")
        statflag_qfactor = octets_to_binary(octet_statflag_qfactor, 1, "big")
        self.stationaryFlag = BitFlag(statflag_qfactor[7], "Stationary Flag")
        # TODO: cast bits back into octet
        #qfactor = '0' + statflag_qfactor[0:7]
        #self.qualityFactor = NumData(qfactor, "Quality Factor", unpack_format='b', endianness="little")

        # temporary Quality Factor computation
        self.qualityFactor = NumData(octet_statflag_qfactor, "Quality Factor", unpack_format='b', endianness="little")

        self.x = NumData(slice_octets(data, 15, 4), "Last Calculated X (m)", unpack_format='<f', endianness="little")
        self.y = NumData(slice_octets(data, 19, 4), "Last Calculated Y (m)", unpack_format='<f', endianness="little")
        self.z = NumData(slice_octets(data, 23, 4), "Last Calculated Z (m)", unpack_format='<f', endianness="little")
        self.padding = OctetData(slice_octets(data, 27, 2, endianness="little"), "Padding", False)

        # store message data
        self.data = OctetData(data, "Group Poll Message", False)
        self.length = self.LENGTH  # no. octets

    def to_string(self):
        return self.data.to_string()  # Group Poll message data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Group Poll message
        data_str += "Length: " + str(self.length) + "\n"    # Group Poll message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.flags.to_string() + "\n"  # Flags
        data_str += indented + self.updatePeriod.to_string() + "\n"  # Update Period
        data_str += indented + self.address0.to_string() + "\n"  # Address of anchor 0
        data_str += indented + self.address1.to_string() + "\n"  # Address of anchor 1
        data_str += indented + self.address2.to_string() + "\n"  # Address of anchor 2
        data_str += indented + self.address3.to_string() + "\n"  # Address of anchor 3
        data_str += indented + self.sequenceNumber.to_string() + "\n"  # TWR Sequence Number
        data_str += indented + self.stationaryFlag.to_string() + "\n"  # Stationary Flag
        data_str += indented + self.qualityFactor.to_string() + "\n"  # Quality Factor
        data_str += indented + self.x.to_string() + "\n"  # Last Calculated X Coordinate
        data_str += indented + self.y.to_string() + "\n"  # Last Calculated Y Coordinate
        data_str += indented + self.z.to_string() + "\n"  # Last Calculated Z Coordinate
        data_str += indented + self.padding.to_string() + "\n"  # Padding
        # return data
        return data_str

class MsgResponse:
    VARIABLE_LENGTH = False
    LENGTH = 22
    MSG_ID = "31"
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_TWR_POLL"
    def __init__(self, data):
        # decode payload
        # TODO: bits in flags most likely could be flipped
        self.flags = OctetData(slice_octets(data, 1, 1, endianness="little"), "Flags", True, endianness="little")
        self.slotMap = OctetData(slice_octets(data, 2, 2, endianness="little"), "Slot Map", True)
        # TODO: Decode timestamp
        self.gpTimestamp = OctetData(slice_octets(data, 4, 4, endianness="little"), "Group Poll (GP) Timestamp", False)
        self.rTimestamp = OctetData(slice_octets(data, 8, 4, endianness="little"), "R (Response) TX Timestamp", False)  # This message (Response) TX timestamp
        self.nonce = OctetData(slice_octets(data, 12, 10, endianness="little"), "NONCE", False)
        # store message data
        self.data = OctetData(data, "Response Message", False)
        self.length = self.LENGTH  # no. octets

    def to_string(self):
        return self.data.to_string()  # Response message data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Response message
        data_str += "Length: " + str(self.length) + "\n"    # Response message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.flags.to_string() + "\n"  # Flags
        data_str += indented + self.slotMap.to_string() + "\n"  # Slot Map
        data_str += indented + self.gpTimestamp.to_string() + "\n"  # GP Timestamp
        data_str += indented + self.rTimestamp.to_string() + "\n"  # R Timestamp
        data_str += indented + self.nonce.to_string() + "\n"  # NONCE
        # return data
        return data_str

class MsgBridgeNodeBeacon:
    VARIABLE_LENGTH = True
    MAX_LENGTH = 40
    HEADER_LENGTH = 10
    MSG_ID = "6a"
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_BN_BCN"
    def __init__(self, data):
        # decode payload
        self.clusterMap = OctetData(slice_octets(data, 1, 4, endianness="little"), "Cluster Map", True, endianness="big")   # occupied BN cluster seats visible by the sending anchor
        self.address = OctetData(slice_octets(data, 5, 2, endianness="little"), "Address", False)   # address of joining bridge node
        self.bnClusterLock = OctetData(slice_octets(data, 7, 1, endianness="little"), "BN Cluster Lock", False)  # Lock counter (decrementing)
        self.bnClusterSeat = OctetData(slice_octets(data, 8, 1, endianness="little"), "BN Cluster Seat", False)  # Confirming allocated BN cluster seat number
        self.count = NumData(slice_octets(data, 9, 1, endianness="little"), "No. tag addresses", unpack_format='b') # Number of tag addresses
        # TODO: Verify tag addresses
        self.tagAddresses = []
        for i in range(self.count):
            startOctet = 10 + (i*2)
            self.tagAddresses.append(Data(slice_octets(data, startOctet, 2, endianness="little"), "Tag Address {}".format(i), False))    # Tag address
        # store message data
        self.length = self.HEADER_LENGTH + 2*self.count.value
        self.data = OctetData(slice_octets(data, 0, self.length, endianness="big"), "Bridge Node Beacon Message", False)

    def to_string(self):
        return self.data.to_string()  # Response message data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Bridge Node Beacon message
        data_str += "Length: " + str(self.length) + "\n"    # Bridge Node Beacon message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.clusterMap.to_string() + "\n"
        data_str += indented + self.address.to_string() + "\n"
        data_str += indented + self.bnClusterLock.to_string() + "\n"
        data_str += indented + self.bnClusterSeat.to_string() + "\n"
        data_str += indented + self.count.to_string() + "\n"
        for i in range(self.count):
            data_str += indented + self.tagAddresses[i].to_string() + "\n"
        # return data
        return data_str

class MsgIotDataDownlink:
    VARIABLE_LENGTH = True
    MAX_LENGTH = 41
    HEADER_LENGTH = 7
    MSG_ID = "63" # for downlink
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_DL_IOT_DATA"
    def __init__(self, data):
        # decode payload
        # TODO: bits in flags most likely could be flipped
        self.id = OctetData(slice_octets(data, 1, 2, endianness="little"), "ID", False)
        self.flags = OctetData(slice_octets(data, 3, 1, endianness="little"), "Flags", True)
        # TODO: Decode update rate
        self.updateRate = OctetData(slice_octets(data, 4, 2, endianness="little"), "Update Rate", False)
        self.dataLength = NumData(slice_octets(data, 6, 1, endianness="little"), "Data Length", unpack_format='b')
        self.iotPayload = OctetData(slice_octets(data, 7, self.dataLength.value, endianness="little"), "IOT Payload", False)
        # store message data
        self.length = self.dataLength.value + self.HEADER_LENGTH
        self.data = OctetData(slice_octets(data, 0, self.length, endianness="big"), "Downlink IOT Data Message", False)

    def to_string(self):
        return self.data.to_string()  # Response message data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # IOT Payload (Downlink) message
        data_str += "Length: " + str(self.length) + "\n"    # IOT Payload (Downlink) message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.id.to_string() + "\n"
        data_str += indented + self.flags.to_string() + "\n"
        data_str += indented + self.updateRate.to_string() + "\n"
        data_str += indented + self.dataLength.to_string() + "\n"
        data_str += indented + self.iotPayload.to_string() + "\n"
        # return data
        return data_str

class MsgIotDataUplink:
    VARIABLE_LENGTH = True
    MAX_LENGTH = 41
    HEADER_LENGTH = 7
    MSG_ID = "65" # for uplink
    MSG_ID_NAME = "UWBMAC_FRM_TYPE_UL_IOT_DATA"
    def __init__(self, data):
        # decode payload
        # TODO: bits in flags most likely could be flipped
        self.id = OctetData(slice_octets(data, 1, 2, endianness="little"), "ID", False)
        self.flags = OctetData(slice_octets(data, 3, 1, endianness="little"), "Flags", True)
        # TODO: Decode update rate
        self.updateRate = OctetData(slice_octets(data, 4, 2, endianness="little"), "Update Rate", False)
        self.dataLength = NumData(slice_octets(data, 6, 1, endianness="little"), "Data Length", unpack_format='b')
        self.iotPayload = OctetData(slice_octets(data, 7, self.dataLength.value, endianness="little"), "IOT Payload", False)
        # store message data
        self.length = self.dataLength.value + self.HEADER_LENGTH
        self.data = OctetData(slice_octets(data, 0, self.length, endianness="big"), "Uplink IOT Data Message", False)

    def to_string(self):
        return self.data.to_string()  # Response message data

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # IOT Payload (Uplink) message
        data_str += "Length: " + str(self.length) + "\n"    # IOT Payload (Uplink) message length
        data_str += indented + "Message ID: {0} ({1})".format(self.MSG_ID, self.MSG_ID_NAME) + "\n"  # Message ID
        # Message contents
        data_str += indented + self.id.to_string() + "\n"
        data_str += indented + self.flags.to_string() + "\n"
        data_str += indented + self.updateRate.to_string() + "\n"
        data_str += indented + self.dataLength.to_string() + "\n"
        data_str += indented + self.iotPayload.to_string() + "\n"
        # return data
        return data_str


class MessagePayload:
    MSG_TYPES = [MsgBeacon, MsgJoinRequest, MsgJoinConfirmation, MsgAlmanac, MsgPosition, MsgGroupPoll, MsgResponse, MsgIotDataDownlink, MsgIotDataUplink]
    def __init__(self, data):
        # store the data
        self.data = OctetData(data, "Payload", False)
        # decode the data into DWM1001 messages
        self.messages = []
        self.decode_dwm1001_messages()
    
    def decode_dwm1001_messages(self):
        # iterate through each octet until a valid message ID is encountered
        i = 0  # octet iterator
        while i < self.data.length:
            # get current octet
            octet = self.data.data[i*2 : (i+1)*2]
            # check if octet matches a message ID
            # TODO: only Beacon frames may have certain specific messages appended to it
            for msgType in self.MSG_TYPES:  # TODO: change to dictionary
                if octet == msgType.MSG_ID:
                    message = msgType(self.data.data[i*2:])
                    self.messages.append(message)
                    i += message.length
            else:
                i += 1

    def data_breakdown(self, num_spaces):
        start_spacing = ""
        for i in range(num_spaces):
            start_spacing += "  "
        indented = start_spacing + "  "
        data_str = ""
        # Message metadata
        data_str += start_spacing + self.data.to_string() + " - "   # Total Payload
        data_str += "Length: " + str(self.data.length) + "\n"    # Payload length
        # Message contents
        for msg in self.messages:
            data_str += msg.data_breakdown(num_spaces+1)
        # return data
        return data_str