import socket
import sys
from struct import *
import csv

# Ethetnetten gecen paketlere ulasmak icin
# ntohs(0x0003) ile gelen giden tum paketleri izlemeye aliyoruz
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

while True:
    packet = s.recvfrom(65565)
    # packet string from tuple
    packet = packet[0]
    # parse ethernet header
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    #6s6sH ethernet headerinden geliyor
    #Destination, Sourca Adres ve Type
    # 6s=Hedef mac adresi   6s=Kaynak mac adresi   H=Type
    eth_protocol = socket.ntohs(eth[2])
    #Ethernet basligindan Type eth[2] ile bakilarak hangi protocol oldugu ogrenildi
    #dosya = open("logg", "a")
    #dosya.write('\nDestination MAC : ' + eth_addr(packet[0:6]) + '\nSource MAC : ' + eth_addr( packet[6:12]) + '\nProtocol : ' + str(eth_protocol))

    # IP paketlerini inceleyelim
    if eth_protocol == 8:
        #IP ethernet frameden sonra baslar ve uzunlugu 20 byte'tir
        ipheader = packet[eth_length:20 + eth_length]
        #IP basligini acip icinden ayrim yapalim
        iph = unpack('!BBHHHBBH4s4s', ipheader)
        #BBHHHBBH4s4s IP basligindan gelmektedir B=1byte(8 bit)  H=2byte(16 bit) 4s=4byte(32bit) ifade etmektedir
        #B=Version+IHL B=ToS H=Total Length H=Identification H=Flag+Fragment Ofset B=TTL B=Protocol H=Checksum
        #4s=Source Adres  4s=Dest Adres
        #Yani bu adresleri kac bit ile temsil edildigi gosterilmektedir
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        src_addr = socket.inet_ntoa(iph[8])
        dst_addr = socket.inet_ntoa(iph[9])
        dosya = open("logg", "a")
        dosya.write ('\n\nVersion : ' + str(version) + '\nIP Header Length : ' + str(ihl) + '\nTTL : ' + str(ttl) + \
              '\nProtocol : ' + str(protocol) + '\nSource Address : ' + str(src_addr) + '\nDestination Address : '+ str(dst_addr))
       # with open('log.csv','w') as csvfile:
       #     fieldnames=['Version', 'IP Header Length', 'TTL', 'Protocol', 'Source Address', 'Destination Address']
       #     writer=csv.DictWriter(csvfile,fieldnames=fieldnames)
       #     writer.writeheader()
       #     writer.writerow({'Version': str(version) , 'IP Header Length': str(ihl) , 'TTL': str(ttl) ,'Protocol' : str(protocol) ,
       #                   'Source Address' : str(src_addr) ,'Destination Address': str(dst_addr)})
        # TCP protokolu inceleyelim
        if protocol == 6:
            #TCP basligi ethernet ve ip den sonra gelmektedir ve 20 byte'tir
            t = iph_length + eth_length
            tcp_header = packet[t:t + 20]
            #TCP basligini ayristiralim
            tcph = unpack('!HHLLBBHHH', tcp_header)
            #H=Kaynak port numarasi  H=Hedef port numarasi  L=Sequence numarasi L=ACK numarasi
            #B=Data ofset + rezerve  B=Control flag   H=Window size H=Checksum   H=Pointer
            src_port = tcph[0]
            dst_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doffreserved = tcph[4]
            tcphlength = doffreserved >> 4
            dosya = open("logg", "a")
            dosya.write( '\nSource Port : ' + str(src_port) + '\nDest Port : ' + str(dst_port) +\
                  '\nSequence Number : ' + str(sequence) + '\nAcknowledgement : ' + str(acknowledgement) +\
                  '\nTCP header length : ' + str(tcphlength)+'\n')

        # ICMP Packets
        elif protocol == 1:
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u + 4]
            # now unpack them :)
            icmph = unpack('!BBH', icmp_header)
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
            dosya = open("logg", "a")
            dosya.write( '\nType : ' + str(icmp_type) + '\nCode : ' + str(code) + '\nChecksum : ' + str(checksum)+'\n')
            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

        # UDP packets
        elif protocol == 17:
            #UDP de TCP gibi ethernet ve ip basligindan sonra gelir ve 8 byte'tir
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u + 8]
            #UDP basligini acalim
            udph = unpack('!HHHH', udp_header)
            #H= Kaynak port numarasi   H=Hedef port numarasi   H=Uzunluk   H=Checksum
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
            dosya = open("logg", "a")
            dosya.write( '\nSource Port : ' + str(source_port) + '\nDest Port : ' + str(dest_port) + '\nLength : ' + str(length)\
                  + '\nChecksum : ' + str(checksum)+'\n')
