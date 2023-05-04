import re
import Part2

class WebsiteDomain:
    def __init__(self, body) -> None:
        # Get packet body from Loop.py and convert it to hex
        self.body = int.from_bytes(body, 'big')
        self.body = hex(self.body)

        # Convert 'top' to hexadecimal
        domainName = 'top'.encode('utf-8')
        domainName = domainName.hex()

        # Get and find the protocol of the packet 
        protocol = int.from_bytes(body[23:24], 'big')
        protocol = Part2.DHCP.protocolCalc(self, str(protocol))

        self.breaker = 0

        # Configuration of a regular expression to search for 'top' within the packet body
        regex = re.search(domainName, self.body[42:])

        # Skim through .PCAP file to find packet which uses UDP protocol
        # and contains an exact match of the hex value of 'top'
        if regex and protocol == 'UDP':
            self.body = self.body[84:] # Skip to the Domain Name System
            self.breaker = self.DNSPacket()
        else:
            pass

    # Assigning the values within the DNS frame
    def DNSPacket(self):
        transactionID = self.body[:4] 
        flags = self.body[4:8] 
        questions = self.body[8:12] 
        ansRRs = self.body[12:16] 
        athRRs = self.body[16:20] 
        addRRs = self.body[20:24] 

        self.name = self.body[24:82] # Extracting DNS query name 
        self.convName()
        return 1

    # Convert name into readable data
    def convName(self):
        self.name = bytes.fromhex(self.name)
        self.name = self.name.decode('ascii')

        self.DNSname = self.name[:17] + '.' + self.name[17:24] + '.' + self.name[24:]
        print('\nDNS Query Name = ' + self.DNSname)

    def loopBreaker(self):
        return self.breaker # Break loop if the 

class SearchEngine:
    def __init__(self, body) -> None:
        self.body = int.from_bytes(body, 'big')
        self.body = hex(self.body)

        self.loopBreaker = 0
        # Creating a list to contain website domains 
        domain = []

        # converting the domain of the most famous search engines into hex figures and appendign them to the list previously created
        bingDomain = 'bing'.encode('utf-8').hex()
        yandexDomain = 'yandex'.encode('utf-8').hex()
        duckduckgoDomain = 'duckduckgo'.encode('utf-8').hex()
        ecosiaDomain = 'ecosia'.encode('utf-8').hex()
        braveDomain = 'brave'.encode('utf-8').hex()
        googleDomain = 'google'.encode('utf-8').hex()

        domain.append(bingDomain)
        domain.append(yandexDomain)
        domain.append(duckduckgoDomain)
        domain.append(ecosiaDomain)
        domain.append(braveDomain)
        domain.append(googleDomain)

        # Extract the protocol of each packet that is analysed
        protocol = int.from_bytes(body[23:24], 'big')
        protocol = Part2.DHCP.protocolCalc(self, str(protocol))

        # loop through all packets for packets using the UDP protocol and include one of the domains listed in the domain list
        for i in domain:
            regex = re.search(i, self.body[42:])
            if regex and protocol == 'UDP':
                engine = i
                self.loopBreaker = self.searchEngine(engine) # once condition has been met break out of the loop

    def searchEngine(self, search_engine):
        search_engine = bytes.fromhex(search_engine)
        search_engine = search_engine.decode('ascii')
        print('Search Engine = ' + search_engine + '\n')

        return 1

    def breaker(self):
        return self.loopBreaker