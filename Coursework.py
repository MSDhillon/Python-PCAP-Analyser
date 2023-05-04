import Loop

# Class to analyse Global Header of PCAP file
class PCAPHeader:
    def __init__(self) -> None:
        self.pcapfile = open('CyberSecurity2023.pcap', 'rb') # Read file as bytes
        print('\nThe Global Header has a fixed length of 24 bytes')

        #Read first 24 bytes of .PCAP file
        magic = self.pcapfile.read(4) # Read first 4 bytes of the global header
        magic = '0x' + str(magic.hex()) # Convert the data into a human readable hexadecimal number
        self.endianness(magic) # Calling function to determine endianness
        print('\nMagic Number = ' + str(magic))

        majorversion = self.conversion(2) # Read 2 bytes which is the major version
        minorversion = self.conversion(2) # Read 2 bytes which is the minor version
        timezone = self.conversion(4) # Read 4 bytes which is the timezone
        timestamp = self.conversion(4) # Read 4 bytes which is the timestamp
        snaplen = self.conversion(4) # Read 4 bytes which is the lenght 
        linktype = self.conversion(4) # Read 4 bytes which is the link type
        print('Major Version = ' + str(majorversion))
        print('Minor Version = ' + str(minorversion))
        print('Timezone = ' + str(timezone))
        print('Timestamp = ' + str(timestamp))
        print('Snap Length = ' + str(snaplen))
        print('Link Type = ' + str(linktype))

        self.pcapfile.close()
        Loop.Parsing(self.endianness)

    # Calculating the endianness of the magic number
    # Depending on the order of the magic number endianness can be defined as big or little endian
    def endianness(self, magic):
        if magic == '0xa1b2c3d4':
            print('\nThe PCAP file uses Big Endian')
            self.endianness = 'big'
        elif magic == '0xd4c3b2a1':
            print('\nThe PCAP file uses Little Endian')
            self.endianness = 'little'

    # Converting data from global header into readable hexadecimal data using the endianness
    def conversion(self, bytes):
        data = self.pcapfile.read(bytes)
        data = int.from_bytes(data, self.endianness) # Converting data from bytes to integers to then change it into a hexadecimal figure
        data = hex(data)
        return data

if __name__ == '__main__':
    PCAPHeader()
