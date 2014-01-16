#! /usr/bin/env python

from scapy.all import *


class DHCPv6Library:

	def __init__(self, interface):
		self.__interface = interface
		self.mac = RandMAC()

        def send_solicit(self, macAddr="", type="IAPD", t1=0, t2=0):
		if macAddr:
			self.mac = macAddr
		self.ether = Ether(dst="33:33:00:01:00:02", src=self.mac)
		self.ipv6 = IPv6(src="fe80::20e:7bff:febb:a38a", dst="ff02::1:2")
		self.udp = UDP(sport=546, dport=547)
		self.clientid = DHCP6OptClientId()
		self.clientid.duid = DUID_LL(lladdr=self.mac)
		self.iapd = DHCP6OptIA_PD(iaid=4, T1=150000, T2=200000)
		self.elapsedTime = DHCP6OptElapsedTime()
		solicit = DHCP6_Solicit(trid=0xbadc70)

		solicitPacket = (self.ether/self.ipv6/self.udp/solicit/self.clientid/self.iapd/self.elapsedTime)
 		self.ans,unans=srp(solicitPacket, iface=self.__interface)

	def send_request(self, t1=0, t2=0):
		request = DHCP6_Request(trid=0xbadc70)
                serverId = self.ans[0][1][DHCP6OptServerId]
		if t1:
			ans[0][1][DHCP6OptIA_PD].T1 = t1
		if t2:
			ans[0][1][DHCP6OptIA_PD].T2 = t2
		packet = (self.ether/self.ipv6/self.udp/request/self.clientid/serverId/self.elapsedTime)
                sendp(packet, iface=self.__interface)

	def get_mac(self):
		return self.mac

	def get_returned_prefix(self):
		prefix = self.ans[0][1][DHCP6OptIAPrefix].prefix
		return prefix
			
