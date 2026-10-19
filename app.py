from flask import Flask, render_template
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
import socket
import threading

app = Flask(__name__)

target_ip = "192.168.29.0/24"

ports = [21, 22, 80, 443, 445, 8080]


mac_lookup = MacLookup()

def scan_ports(ip):

    open_ports = []

    for port in ports:

        try:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(1)

            result = sock.connect_ex((ip, port))

            if result == 0:
                open_ports.append(port)

            sock.close()

        except:
            pass

    return open_ports

def scan_network():

    devices = []

    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    threads = []

    def process_device(received):

        ip = received.psrc
        mac = received.hwsrc

       
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

    
        try:
            vendor = mac_lookup.lookup(mac)
        except:
            vendor = "Unknown"

        open_ports = scan_ports(ip)

        devices.append({
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor': vendor,
            'ports': open_ports
        })

    for sent, received in result:

        thread = threading.Thread(
            target=process_device,
            args=(received,)
        )

        threads.append(thread)

        thread.start()

    for thread in threads:
        thread.join()

    return devices

@app.route('/')

def home():

    devices = scan_network()

    return render_template(
        'index.html',
        devices=devices
    )
if __name__ == '__main__':

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
