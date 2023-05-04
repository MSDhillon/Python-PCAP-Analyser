from datetime import datetime
import Part2
import Part3
import PScanner

# Class to store packet data within variables
class Packet():
    def __init__(self, timestamp, timestampM, length, ogLength, body) -> None:
        self.timestamp = timestamp
        self.timestampM = timestampM
        self.length = length
        self.ogLength = ogLength
        self.body = body

# Class to analyse packet data
class Parsing:
    def __init__(self, endianness) -> None:
        self.packets = [] 
        self.pcapfile = open('CyberSecurity2023.pcap', 'rb')
        self.endianness = endianness
        self.pcapfile.seek(24, 0) # from the start of the packet skip 24 bytes (which is the global header)

        loop = 0
        
        # while loop which scans all packets within the pcap file and extracts: TIMESTAMP IN SECONDS, TIMESTAMP IN MILLISECONDS, PACKET LENGTH, ORIGINAL PACKET LENGTH AND BODY OF THE PACKET
        while True:
            timestampSec = int.from_bytes(self.pcapfile.read(4), self.endianness)
            if not timestampSec:
                break
            timestampSec = self.timeConversion(timestampSec)
            timestampMsec = int.from_bytes(self.pcapfile.read(4), self.endianness)
            packetLen = int.from_bytes(self.pcapfile.read(4), self.endianness)
            ogPacketLen = int.from_bytes(self.pcapfile.read(4), self.endianness)
            body = self.pcapfile.read(packetLen) # skip the data inside the packet
            self.packets.append(Packet(timestampSec, timestampMsec, packetLen, ogPacketLen, body)) # store all data extracted in the lit self.packets using the class Packet
            loop += 1
        self.pcapfile.close()

        print('\nTotal number of packets:', loop)

        print('\nArrival Time = ' + str(self.packets[0].timestamp) + '.' + str(self.packets[0].timestampM))

        Part2.DHCP(self.packets[0].body) # sending the first packet's body to the next class

        loop = 0
        # scanning through all packets in the pcap file to find the website domain and break the loop when it's found
        for elements in self.packets:
            x = Part3.WebsiteDomain(self.packets[loop].body)
            if x.loopBreaker() == 1:
                break
            loop += 1

        # scanning through all packets in the pcap file to find the search engine and break the loop when it's found
        loop = 0
        for elements in self.packets:
            y = Part3.SearchEngine(self.packets[loop].body)
            if y.breaker() == 1:
                break
            loop += 1

        PScanner.runScanner()

    # Function to convert the timestamp in date and time format using datetime library
    def timeConversion(self, timestamp):
        td = datetime.fromtimestamp(timestamp).strftime("%A, %B %d, %Y %H:%M:%S")
        return td
