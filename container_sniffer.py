#!/usr/bin/env python3
# vim: ts=4 sw=4
# A small program to capture which container is sending traffic to a specific IP.
import socket
import struct
import binascii
import docker
import time
from threading import Thread

# capture_interface = "br-4387c114197f"
capture_dest_ip = "192.168.1.87"

verbose = True
very_verbose = False

# gloabl variable to hold container info
container_info = {}

class ContainerInfo(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.client = docker.DockerClient()
        self.daemon = True
        self.start()

    def run(self):
        global container_info
        if verbose:
            print("container_thread: started")
        while(True):
            if verbose:
                print("container_thread: start retrieve container info")
            for container in self.client.containers.list(all=True):
                if very_verbose:
                    print("container_thread: get ip of container {}".format(container.name))
                for container_network in container.attrs['NetworkSettings']['Networks']:
                    container_ip = container.attrs['NetworkSettings']['Networks'][container_network]['IPAddress']

                    if 'com.nirima.jenkins.plugins.docker.JenkinsServerUrl' in container.attrs['Config']['Labels']:
                        if very_verbose:
                            print("container_thread: found JenkinsServerUrl label")
                        container_info[container_ip] = {'name': container.name,
                                    'JenkinsServerUrl': container.attrs['Config']['Labels']['com.nirima.jenkins.plugins.docker.JenkinsServerUrl'] }
                    else:
                        if very_verbose:
                            print("container_thread: could not find a JenkinsServerUrl label on container {}".format(container.name))
                        container_info[container_ip] = { 'name': container.name,
                                    'JenkinsServerUrl': 'not found' }
            if verbose:
                print("container_thread: done fetching info sleeping for 5 seconds")
            time.sleep(5)

class PacketCapture(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.daemon = True
        self.start()

    def run(self):
        if verbose:
            print("packet capture thread: started")
        global capture_dest_ip
        self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        try:
            self.raw_socket.setsockopt(socket.SOL_SOCKET, 25, str(bind_nic + '\0').encode('utf-8'))
            self.raw_socket.ins.bind((iface, 0x0800))
        except NameError:
            print("packet capture thread: using all interfaces")
        while True:
            self._pkt = self.raw_socket.recvfrom(2048)
            self._ip_header = self._pkt[0][14:34]
            self._ip_hdr = struct.unpack("!12s4s4s", self._ip_header) # 12s represents Identification, Time to Live, Protocol | Flags, Fragment Offset, Header Checksum
            self._tcp_header = self._pkt[0][34:54]
            try:
                self._tcp_hdr = struct.unpack("!HHLLBBHHH", self._tcp_header)
                self.src_ip  = socket.inet_ntoa(self._ip_hdr[1])
                self.dest_ip = socket.inet_ntoa(self._ip_hdr[2])
                if str(self.dest_ip) == capture_dest_ip:
                    if self._tcp_hdr[5] & 0x002: # SYN Packet
                        if self.src_ip in container_info:
                            print("{},{},{},{}".format(self._src_ip,self._dest_ip,container_info[self.src_ip]['name'],container_info[self.src_ip]['JenkinsServerUrl']))
                        else:
                            print("{},{},{},{}".format(self.src_ip,self.dest_ip,"ContainerNotFound","NotFound"))
            except Exception as e:
                print("Got an error: {}".format(e))


def main():
    ContainerInfo()
    PacketCapture()
    while(True):
        pass

if __name__ == "__main__":
    main()