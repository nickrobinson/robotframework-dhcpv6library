#! /usr/bin/env python

from scapy.all import *
import random

class DHCPv6Library:

	def __init__(self, interface):
		self.__interface = interface
       		self.transactionId = random.randint(0, 1677215)
		M=16**2
		self.mac = "b2:39:4b:b8:45:" + ":".join("%x" % random.randint(0, M) for i in range(1))
 
	def send_solicit(self, mac="", type="IAPD", t1=0, t2=0, srcIp ="fe80::20e:7bff:febb:a38a", rapidCommit=False):
		if mac:
			self.mac = mac
		self.clientid = DHCP6OptClientId()
		self.clientid.duid = DUID_LL(lladdr=self.mac)
		self.ether = Ether(dst="33:33:00:01:00:02", src=self.mac)
		self.ipv6 = IPv6(src=srcIp, dst="ff02::1:2")
		self.udp = UDP(sport=546, dport=547)
		self.iapd = DHCP6OptIA_PD(iaid=4, T1=150000, T2=200000)
		self.iana = DHCP6OptIA_NA(iaid=4, T1=150000, T2=200000)
		self.elapsedTime = DHCP6OptElapsedTime()
		solicit = DHCP6_Solicit(trid=self.transactionId)
		solicitPacket = ""
		if rapidCommit:
			rapidCommit = DHCP6OptRapidCommit()
			solicitPacket = (self.ether/self.ipv6/self.udp/solicit/self.clientid/self.iapd/rapidCommit/self.elapsedTime)
		else:
			print "Type is: " + type
			if type == "IANA":
				solicitPacket = (self.ether/self.ipv6/self.udp/solicit/self.clientid/self.iana/self.elapsedTime)
			else:
				solicitPacket = (self.ether/self.ipv6/self.udp/solicit/self.clientid/self.iapd/self.elapsedTime)

		self.ans,unans=srp(solicitPacket, iface=self.__interface, timeout=2)

	def send_request(self, t1=0, t2=0):
		request = DHCP6_Request(trid=0xbadc70)
                serverId = self.ans[0][1][DHCP6OptServerId]
		if t1:
			ans[0][1][DHCP6OptIA_PD].T1 = t1
		if t2:
			ans[0][1][DHCP6OptIA_PD].T2 = t2
		packet = (self.ether/self.ipv6/self.udp/request/self.clientid/serverId/self.elapsedTime)
                sendp(packet, iface=self.__interface)

	def send_renew(self, t1=0, t2=0):
		renew = DHCP6_Renew(trid=0xbadc71)
		serverId = self.ans[0][1][DHCP6OptServerId]
		if t1:
			ans[0][1][DHCP6OptIA_PD].T1 = t1
		if t2:
			ans[0][1][DHCP6OptIA_PD].T2 = t2
		packet = (self.ether/self.ipv6/self.udp/renew/self.clientid/serverId/self.elapsedTime)
		sendp(packet, iface=self.__interface)

	def get_returned_prefix(self):
		print "Getting prefix from answer"
		prefix = self.ans[0][1][DHCP6OptIAPrefix].prefix
		return prefix

	def get_mac(self):
		return self.mac

	def randomize_mac(self):
		M = 16**2
		self.mac = "b2:39:4b:b8:45:" + ":".join("%x" % random.randint(0, M) for i in range(1))

	def get_duid(self):
		newMac = str(self.mac)
		print "get_duid: MAC Address: %s" % self.mac
		newMac = newMac.replace(":", "")
		duid = newMac.upper()
		return "00030001"+duid

	def get_ip_address(self):
		random.seed()
		M = 16**4
		ip = "2001:cafe:" + ":".join(("%x" % random.randint(0, M) for i in range(1)))
		ip = ip + "::/56"
		return ip
