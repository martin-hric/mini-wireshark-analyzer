from scapy.all import *
from binascii import *
from collections import Counter

path = 'vzorky_pcap_na_analyzu/trace-27.pcap'

class a_ramec():
        number: int
        length_pcap_API: str
        length_medium: str
        payload: str
        d_length: str
        src_mac: str
        dst_mac: str
        type:str
        protocol_2: str
        protocol_3: str
        protocol_4: str
        src_port: str
        dst_port: str
        l_port:str
        src_ipv4: str
        dst_ipv4: str
        druh:str

def uloz_pcap_do_txt():
    paket = rdpcap(path)
    textak = open('paket.txt','w')

    for ramec in paket:
        textak.write(hexlify(raw(ramec)).decode()+'\n')

    textak.close()

#organizuje vsetko
def vypis():
    textak =open('paket.txt','r')
    a_textak=open('analyzovany_paket.txt','w',encoding='utf-8')
    arp_paket=open('arp_paket.txt','w')
    icmp_paket=open('icmp_paket.txt','w')
    lldp_subor=open('lldp.txt','w')
    lldp_subor.write('LLDP ramce: \n')
    a_textak.write('subor: '+path + '\n')
    dict=read_types()
    ipv4_list=[]
    a_ramec.number=1
    arp=0
    icmp=0
    lldp=0
    for ramec in textak:

        a_ramec.length_pcap_API=int((len(ramec)-1)/2)
        a_ramec.length_medium=a_ramec.length_pcap_API + 4
        if a_ramec.length_medium <64:
            a_ramec.length_medium=64

        a_ramec.d_length = ramec[24:28]
        a_ramec.payload=ramec[28:30]

        if int(a_ramec.d_length,16)>1500:
            a_ramec.type = 'Ethernet II'
        elif a_ramec.payload == 'ff' and int(a_ramec.d_length,16) <= 1500:
            a_ramec.type = 'IEEE 802.3 RAW'
            a_ramec.protocol_3='IPX'
        elif a_ramec.payload == 'aa' and int(a_ramec.d_length,16) <= 1500:
            a_ramec.type = 'IEEE 802.3 LLC + SNAP'
        else:
            a_ramec.type='IEEE 802.3 LLC'

        a_ramec.d_length=a_ramec.d_length.upper()
        a_ramec.protocol_2=find_protocol(a_ramec.d_length,dict,'#Ethertypes')

        a_ramec.dst_mac=ramec[:12]
        a_ramec.src_mac=ramec[12:24]
        a_ramec.payload=ramec[28:30]
        a_ramec.protocol_3=ramec[46:48]

        if a_ramec.protocol_2=='IPv4':
            a_ramec.src_ipv4=convert_hexString_to_IP(ramec[52:60])
            a_ramec.dst_ipv4=convert_hexString_to_IP(ramec[60:68])

        a_ramec.src_port=int(ramec[68:72],16)
        a_ramec.dst_port=int(ramec[72:76],16)
        a_ramec.l_port=min(a_ramec.src_port,a_ramec.dst_port)

        a_ramec.protocol_3=find_protocol(a_ramec.protocol_3,dict,'#IP')
        if a_ramec.protocol_3=='ICMP':
            a_ramec.druh=''
            if a_ramec.protocol_2=='IPv4':
                icmp=icmp+1
                icmp_paket.write(str(a_ramec.number)+'\n'+ramec)
        elif a_ramec.protocol_3=='':
            a_ramec.druh=''
        elif a_ramec.protocol_3 == 'TCP':
            a_ramec.druh = '#TCP ports'
        elif a_ramec.protocol_3=='UDP':
            a_ramec.druh='#UDP ports'

        a_ramec.protocol_4=find_protocol(a_ramec.l_port,dict,a_ramec.druh)

        if a_ramec.protocol_2 == 'IPv4':
            ipv4_list.append(a_ramec.src_ipv4)
        elif a_ramec.protocol_2 == 'ARP':
            arp=arp+1
            arp_paket.write(str(a_ramec.number)+'\n'+ramec)
        elif a_ramec.protocol_2=='LLDP':
            lldp=lldp+1

        if a_ramec.protocol_2=='LLDP':
            lldp_subor.write('ramec: '+str(a_ramec.number)+'\n')


        a_textak.write('----------------------------------- ramec: '+str(a_ramec.number)+'----------------------------------'+'\n')
        a_textak.write('dĺžka rámca poskytnutá pcap API: '+ str(a_ramec.length_pcap_API)+'B'+'\n')
        a_textak.write('dĺžka rámca prenášaného po médiu: ' + str(a_ramec.length_medium) + 'B'+'\n')
        a_textak.write(a_ramec.type+'\n')

        a_textak.write('Zdrojová MAC adresa')
        for i in range(12):
            if i % 2 == 0:
                a_textak.write(':')
            a_textak.write(a_ramec.src_mac[i])
        a_textak.write('\n')

        a_textak.write('Cieľová MAC adresa')
        for i in range(12):
            if i % 2 == 0:
                a_textak.write(':')
            a_textak.write(a_ramec.dst_mac[i])

        if a_ramec.protocol_2 != '':
            a_textak.write('\n'+a_ramec.protocol_2)
            if a_ramec.protocol_2 == 'IPv4':
                a_textak.write('\nZdrojová IP adresa: '+a_ramec.src_ipv4)
                a_textak.write('\nCielova IP adresa: '+a_ramec.dst_ipv4)


        if a_ramec.protocol_2 !='' and a_ramec.protocol_2 !='ARP' and a_ramec.protocol_2!='IPv6':
            a_textak.write('\n'+a_ramec.protocol_3)


        if a_ramec.protocol_3 != '' and a_ramec.protocol_3!='ICMP':
            a_textak.write('\nZdrojovy port: ' + str(a_ramec.src_port))
            a_textak.write('\nCielovy port: ' + str(a_ramec.dst_port))

        if a_ramec.protocol_4 != '':
            a_textak.write('\n'+a_ramec.protocol_4)


        for i in range(a_ramec.length_pcap_API * 2):
            if i % 2 == 0:
                a_textak.write(' ')
            if i % 16 == 0:
                a_textak.write('   ')
            if i % 32 == 0:
                a_textak.write('\n')
            a_textak.write(ramec[i])
        a_textak.write('\n')
        a_ramec.number=a_ramec.number+1

    a_textak.write('-----------------------------------------------------------------------------\n')
    a_textak.write('IP adresy vysielajúcich uzlov:\n')
    pocet=Counter(ipv4_list)
    for element in pocet.keys():
        a_textak.write(str(element)+'\n')
    a_textak.write('Adresa uzla s najväčším počtom odoslaných paketov:\n')
    a_textak.write(str(pocet.most_common(1))+'\n')
    a_textak.write('----------------------------------------------------------------------------\n')
    a_textak.write('pocet LLDP: '+str(lldp)+'\n')
    lldp_subor.write('\npocet LLDP: '+str(lldp))
    textak.close()
    a_textak.close()
    arp_paket.close()
    icmp_paket.close()
    lldp_subor.close()

    if icmp>0:
        icmp_comm()

    if arp>0:
        arp_comm()

#vypisuje icmp komunikacie
def icmp_comm():
    icmp_paket=open('icmp_paket.txt','r')
    icmp_textak=open('analyzovany_paket.txt','a',encoding='utf-8')
    dict = read_types()
    icmp_textak.write('-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')
    icmp_textak.write('-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')
    icmp_textak.write('ICMP KOMUNIKACIE: \n')

    for ramec in icmp_paket:
        ramec = ramec.strip()
        if ramec.isdigit():
            cislo_icmp = ramec
            continue
        type=int(ramec[68:70],16)
        typ=find_protocol(type,dict,'#ICMP')
        if typ!='':
            a_ramec.length_pcap_API = int((len(ramec) - 1) / 2)
            a_ramec.length_medium = a_ramec.length_pcap_API + 4
            if a_ramec.length_medium < 64:
                a_ramec.length_medium = 64

            a_ramec.type='Ethernet II'

            a_ramec.protocol_2 = 'IPv4'

            a_ramec.dst_mac = ramec[:12]
            a_ramec.src_mac = ramec[12:24]

            if a_ramec.protocol_2 == 'IPv4':
                a_ramec.src_ipv4 = convert_hexString_to_IP(ramec[52:60])
                a_ramec.dst_ipv4 = convert_hexString_to_IP(ramec[60:68])

            a_ramec.protocol_3 = 'ICMP'

            icmp_textak.write('----------------------------------- ramec: ' + str(cislo_icmp) + '----------------------------------' + '\n')
            icmp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(a_ramec.length_pcap_API) + 'B' + '\n')
            icmp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(a_ramec.length_medium) + 'B' + '\n')
            icmp_textak.write(a_ramec.type + '\n')

            icmp_textak.write('Zdrojová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    icmp_textak.write(':')
                icmp_textak.write(a_ramec.src_mac[i])
            icmp_textak.write('\n')

            icmp_textak.write('Cieľová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    icmp_textak.write(':')
                icmp_textak.write(a_ramec.dst_mac[i])

            icmp_textak.write('\n'+a_ramec.protocol_2)
            icmp_textak.write('\nZdrojová IP adresa: ' + a_ramec.src_ipv4)
            icmp_textak.write('\nCielova IP adresa: ' + a_ramec.dst_ipv4)
            icmp_textak.write('\n' + a_ramec.protocol_3)
            icmp_textak.write('\nTyp ICMP komunikacie: '+typ)

            for i in range(a_ramec.length_pcap_API * 2):
                if i % 2 == 0:
                    icmp_textak.write(' ')
                if i % 16 == 0:
                    icmp_textak.write('   ')
                if i % 32 == 0:
                    icmp_textak.write('\n')
                icmp_textak.write(ramec[i])
            icmp_textak.write('\n')

    icmp_textak.write('-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')
    icmp_textak.write('-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')

    icmp_paket.close()
    icmp_textak.close()

#organizuje, ci sa vypisuje uplna/neuplna komunikacia
def arp_comm():
    arp_packet = open('arp_paket.txt', 'r')
    count = 0
    reply_back = 0
    for ramec in arp_packet:
        ramec=ramec.strip()
        if ramec.isdigit():
            cislo_arp=ramec
            continue
        elif ramec[43]=='1':
            typ='request'
        elif ramec[43]=='2':
            typ='reply'

        if typ=='request':
            request_target_IP = convert_hexString_to_IP(ramec[76:84])
            request_sender_IP = convert_hexString_to_IP(ramec[56:64])
            has_reply=find_reply(request_target_IP,request_sender_IP,cislo_arp)

            if has_reply != '':
                count = count + 1
                reply_back=vypis_all_same_req(request_target_IP,request_sender_IP,cislo_arp,has_reply,count)

            else:
               vypis_neuplne_komunikacie(cislo_arp,typ)

        if typ=='reply' and int(reply_back) != int(cislo_arp):
            vypis_neuplne_komunikacie(cislo_arp, typ)

    arp_packet.close()

#zisti, ci ma ARP komunikacia reply
def find_reply(target_IP,sender_IP,cislo):
    arp_textak=open('arp_paket.txt','r')
    for ramec in arp_textak:
        ramec=ramec.strip()
        if ramec.isdigit():
            reply=ramec
            continue
        if int(cislo)>=int(reply):
            continue
        if ramec[43]=='2'and target_IP==convert_hexString_to_IP(ramec[56:64]) and sender_IP==convert_hexString_to_IP(ramec[76:84]):
            arp_textak.close()
            return reply
    return ''
    arp_textak.close()

#vypise neuplne komunikacie
def vypis_neuplne_komunikacie(cislo,typ):
    arp_packet = open('arp_paket.txt', 'r')
    arp_textak = open('analyzovany_paket.txt', 'a', encoding='utf-8')

    for ramec in arp_packet:
        ramec=ramec.strip()
        if ramec.isdigit():
            ciselko=ramec
            continue
        if ciselko ==cislo:
            a_ramec.dst_mac = ramec[:12]
            a_ramec.src_mac = ramec[12:24]

            a_ramec.length_pcap_API = int((len(ramec) - 1) / 2)
            a_ramec.length_medium = a_ramec.length_pcap_API + 4
            if a_ramec.length_medium < 64:
                a_ramec.length_medium = 64

            target_IP = convert_hexString_to_IP(ramec[76:84])
            sender_IP = convert_hexString_to_IP(ramec[54:64])

            arp_textak.write('\nNEUPLNA KOMUNIKACIA:\n')
            arp_textak.write('ARP ' + typ + ', IP adresa: ' + str(target_IP) + '   MAC adresa: ???\nZdrojova IP:' + str(sender_IP) + ',   Cielova IP:' + str(target_IP) + '\n')
            arp_textak.write('----------------------------------- ramec: ' + str(cislo) + '----------------------------------' + '\n')
            arp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(a_ramec.length_pcap_API) + 'B' + '\n')
            arp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(a_ramec.length_medium) + 'B' + '\n')
            arp_textak.write('Ethernet II\n')

            arp_textak.write('Zdrojová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(a_ramec.src_mac[i])
            arp_textak.write('\n')

            arp_textak.write('Cieľová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(a_ramec.dst_mac[i])

            arp_textak.write('\nARP')

            for i in range((a_ramec.length_pcap_API * 2) ):
                if (i) % 2 == 0:
                    arp_textak.write(' ')
                if (i) % 16 == 0:
                    arp_textak.write('   ')
                if (i) % 32 == 0:
                    arp_textak.write('\n')
                arp_textak.write(ramec[i])
            arp_textak.write('\n')

    arp_textak.close()
    arp_packet.close()

#vypise vsetky ramce uplnych arp komunikacii
def vypis_all_same_req(target_IP,sender_IP,cislo_req,cislo_reply,cislo_komunikacie):
    arp_textak=open('analyzovany_paket.txt','a',encoding='utf-8')
    arp_paket=open('arp_paket.txt','r')
    arp_textak.write('\n\nUplna komunikacia cislo: ' + str(cislo_komunikacie)+'\n')
    arp_textak.write('ARP request, IP adresa: ' + str(target_IP) + '   MAC adresa: ???\nZdrojova IP:' + str(sender_IP) + ',   Cielova IP:' + str(target_IP)+'\n')

    for ramec in arp_paket:
        ramec = ramec.strip()
        if ramec.isdigit():
            number=ramec
            continue
        here_sender_IP=convert_hexString_to_IP(ramec[56:64])
        here_target_IP=convert_hexString_to_IP(ramec[76:84])
        if int(number)>=int(cislo_req) and int(number)<int(cislo_reply) and target_IP==here_target_IP and sender_IP==here_sender_IP:
            a_ramec.dst_mac = ramec[:12]
            a_ramec.src_mac = ramec[12:24]

            a_ramec.length_pcap_API = int((len(ramec) - 1) / 2)
            a_ramec.length_medium = a_ramec.length_pcap_API + 4
            if a_ramec.length_medium < 64:
                a_ramec.length_medium = 64

            arp_textak.write('----------------------------------- ramec: ' + str(number) + '----------------------------------' + '\n')
            arp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(a_ramec.length_pcap_API) + 'B' + '\n')
            arp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(a_ramec.length_medium) + 'B' + '\n')
            arp_textak.write('Ethernet II\n')

            arp_textak.write('Zdrojová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(a_ramec.src_mac[i])
            arp_textak.write('\n')

            arp_textak.write('Cieľová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(a_ramec.dst_mac[i])

            arp_textak.write('\nARP')

            for i in range((a_ramec.length_pcap_API * 2) ):
                if (i ) % 2 == 0:
                    arp_textak.write(' ')
                if (i ) % 16 == 0:
                    arp_textak.write('   ')
                if (i ) % 32 == 0:
                    arp_textak.write('\n')
                arp_textak.write(ramec[i])
            arp_textak.write('\n')

        elif int(number)==int(cislo_reply):
            mac_reply=ramec[44:56]
            arp_textak.write('\nARP reply, IP adresa: ' + str(target_IP) + '   MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(mac_reply[i])

            arp_textak.write('\nZdrojova IP:' + str(here_sender_IP) + ',   Cielova IP:' + str(here_target_IP)+'\n')

            a_ramec.dst_mac = ramec[:12]
            a_ramec.src_mac = ramec[12:24]

            a_ramec.length_pcap_API = int((len(ramec) - 1) / 2)
            a_ramec.length_medium = a_ramec.length_pcap_API + 4
            if a_ramec.length_medium < 64:
                a_ramec.length_medium = 64

            arp_textak.write('----------------------------------- ramec: ' + str(number) + '----------------------------------' + '\n')
            arp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(a_ramec.length_pcap_API) + 'B' + '\n')
            arp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(a_ramec.length_medium) + 'B' + '\n')
            arp_textak.write('Ethernet II\n')

            arp_textak.write('Zdrojová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(a_ramec.src_mac[i])
            arp_textak.write('\n')

            arp_textak.write('Cieľová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(a_ramec.dst_mac[i])

            arp_textak.write('\nARP')

            for i in range( (a_ramec.length_pcap_API * 2) ):
                if (i ) % 2 == 0:
                    arp_textak.write(' ')
                if (i ) % 16 == 0:
                    arp_textak.write('   ')
                if (i ) % 32 == 0:
                    arp_textak.write('\n')
                arp_textak.write(ramec[i])
            arp_textak.write('\n')

        elif int(number)>int(cislo_reply):
            return cislo_reply
    return cislo_reply

# convertuje hexstring na IP
def convert_hexString_to_IP(string):
    ip = ["".join(x) for x in zip(*[iter(string)] * 2)]
    ip = [int(x, 16) for x in ip]
    ip = ".".join(str(x) for x in ip)
    return ip

#nacita typy protokolov, portov do dict
def read_types():
    file= open('types.txt','r')
    dict={}
    type=''
    for line in file:
        if line[0]=='#':
            type= line.strip()
            dict[type]={}
        else:
            num, name = line.split(' ',1)
            dict[type][num]= name.rstrip()
    file.close()
    return dict

#najde nazov protokolu z dict
def find_protocol(ciselko,dict,type):
    if type=='':
        return ''
    if str(ciselko) in dict[type]:
        return dict[type][str(ciselko).upper()]
    else: return ''

def main():
    uloz_pcap_do_txt()
    vypis()

main()
