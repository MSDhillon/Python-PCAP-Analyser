
class DHCP:
    def __init__(self, body) -> None:
        MacDestination = int.from_bytes(body[:6], 'big')
        # Removing 0x from the start and filling any 0s missing from the number as hex removes all leading zeros
        MacDestination = hex(MacDestination)[2:].zfill(12)
        MacSource = int.from_bytes(body[6:12], 'big')
        MacSource = hex(MacSource)[2:].zfill(12)
        Type = int.from_bytes(body[12:14], 'big')

        MacDestination = self.macConversion(MacDestination)
        MacSource = self.macConversion(MacSource)

        print('\nDestination = ' + MacDestination)
        print('Source = ' + MacSource)
        self.ethernetType(Type)

        self.InternetProtocolVersion4(body)

        name = body[332:341].decode('ascii') # converting bytes from 332 to 341 to asscii to get hot name
        print('\nHost name = ' + name)

    # Putting the hex number extracted from PCAP file into a MAC address format
    def macConversion(self, address):
        address = ':'.join(format(s, '02x') for s in bytes.fromhex(address))
        return address

    # Calculate Ethernet type depending on the hex number retrieved from packet
    def ethernetType(self, hex):
        if hex == 0x0800:
            print('\nType = IPv4')
        elif hex == 0x86DD:
            print('\nType = IPv6')
    
    def InternetProtocolVersion4(self, body):
        version = int.from_bytes(body[14:15], 'big') 
        diffServices = int.from_bytes(body[15:16], 'big') 

        # extarcting total length of the DCHP frame by reading bytes 16, 17 and 18 of the .pcap file and convert it to integer
        totLength = int.from_bytes(body[16:18], 'big')
        totLength = str(totLength)
        print('Length of DCHP frame = ' + totLength)
        
        identification = int.from_bytes(body[18:20], 'big') 
        
        fragOffSet = int.from_bytes(body[20:22], 'big') 
        
        timeToLive = int.from_bytes(body[22:23], 'big') 
        timeToLive = str(timeToLive)
        
        protocol = int.from_bytes(body[23:24], 'big') # extarcting the protocol used by the packet 
        protocol = self.protocolCalc(str(protocol))# calling a function to convert it 
        print('Protocol = ' + protocol)

        headerCheckSum = int.from_bytes(body[24:26], 'big') 

        # extracting all 4 parts of the source IP address singularly and putting them in format
        sIP1 = int.from_bytes(body[26:27], 'big')
        sIP2 = int.from_bytes(body[27:28], 'big')
        sIP3 = int.from_bytes(body[28:29], 'big')
        sIP4 = int.from_bytes(body[29:30], 'big')
        sourceIP = str(sIP1) + '.' + str(sIP2) + '.' + str(sIP3) + '.' + str(sIP4)
        print('\nSource Address = ' + sourceIP)

        # extracting all 4 parts of the destination IP address singularly and putting them in format
        dIP1 = int.from_bytes(body[30:31], 'big')
        dIP2 = int.from_bytes(body[31:32], 'big')
        dIP3 = int.from_bytes(body[32:33], 'big')
        dIP4 = int.from_bytes(body[33:34], 'big')
        destIP = str(dIP1) + '.' + str(dIP2) + '.' + str(dIP3) + '.' + str(dIP4)
        print('Destination Address = ' + destIP)

        self.UserDatagramProtocol(body) 

    # All UDP data is extracted and stored into these variables
    def UserDatagramProtocol(self, body): 
        sourcePort = int.from_bytes(body[34:36], 'big') 
        destinationPort = int.from_bytes(body[36:38], 'big') 
        length = int.from_bytes(body[38:40], 'big') 
        checksum = int.from_bytes(body[40:42], 'big') 
        data = int.from_bytes(body[42:checksum], 'big') 

    # Determine the data transfer protocol by the extracted data from pcap file
    def protocolCalc(self, data):
        if data == '17':
            return ('UDP')
        elif data == '6':
            return ('TCP')
        else:
            return ("The protocol used isn't TCP or UDP")