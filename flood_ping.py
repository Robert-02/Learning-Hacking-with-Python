import sys
import time
from impacket import ImpactDecoder, ImpactPacket
from scapy.all import *
import subprocess
class Flood_Ping:
    def __init__(self, count, delay, target_host, payload_size, interval):
        self.count = count
        self.delay = delay
        self.target_host = target_host
        self.payload_size = payload_size
        self.interval = interval
        self.network_troubleshooting()
        self.ping_with_subprocess()
        self.ip_spoofing()
        def network_troubleshooting(self):
            icmp_request = IP(dst=self.target_host) / ICMP() / Raw(load=RandString(size=payload_size))
            send(icmp_request, self.count)
            time.sleep(self.interval)
            icmp_response, _ = sr1(icmp_request, timeout=2, verbose=False)
            time.sleep(delay)
            if icmp_response:
                print(icmp_response.show())

        def ping_with_subprocess(self):
            try:
                address = self.target_host
                response = subprocess.call(['ping', '-c', '3', address])
                print("ping to", address, "ok")
            except subprocess.CalledProcessError:
                print("ping to", address, "failed!")
            except Exception as e:
                print(f"An error occurred during ping: {e}")

        def ip_spoofing():
            src = sys.argv[1]
            dst = sys.argv[2]

            # Create a new IP packet and set its source and destination addresses

            self.target_host = ImpactPacket.IP()
            self.target_host.set_ip_src(src)
            self.target_host.set_ip_dst(dst)

            # Create a new ICMP packet

            icmp = ImpactPacket.ICMP()
            icmp.set_icmp_type(icmp.ICMP_ECHO)

            # inlude a small payload inside the ICMP packet
            # and have the ip packet contain the ICMP packet
            icmp.contains(ImpactPacket.Data("a" * 100))
            self.target_host.contains(icmp)

            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # give the ICMP packet some ID
            icmp.set_icmp_id(1)
            # calculate checksum
            icmp.set_icmp_cksum(0)
            icmp.auto_checksum = 0
            s.sendto(target_host.get_packet(), (dst, 0))

        target_host = '127.0.0.1'
        count = 4
        delay = 1  # Define the 'delay' variable
        interval = 0.1
        payload_size = 100
        # Call the functions with the target host
        flood_ping_instance = Flood_Ping(count, delay, target_host, payload_size, interval)
        # Call the methods explicitly when needed
        flood_ping_instance.network_troubleshooting()
        flood_ping_instance.ping_with_subprocess()
        flood_ping_instance.ip_spoofing()