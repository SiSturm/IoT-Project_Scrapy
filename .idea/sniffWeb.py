from scapy.all import *
def arp_display(pkt):
    if pkt[ARP].op == 1: #who-has (request)
        if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
            if pkt[ARP].hwsrc == '34:D2:70:CF:B8:84': # Schwarzkopf
                print ("Pushed Schwarzkopf")
            else:
                print ("ARP Probe from unknown device: " + pkt[ARP].hwsrc)

print (sniff(prn=arp_display, filter="arp", store=0, count=10))