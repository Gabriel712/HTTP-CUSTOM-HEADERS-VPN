import socket
import time
import select
import threading
from inject import injector
import configparser
import ssl
import os
import certifi
import sys

bg = ''
G = bg + '\033[32m'
O = bg + '\033[33m'
GR = bg + '\033[37m'
R = bg + '\033[31m'
Buffer_length = 4096 * 4

class Tun(injector):
    def __init__(self):
        self.localip = '127.0.0.1'
        self.LISTEN_PORT = int(sys.argv[1])

    def conf(self):
        config = configparser.ConfigParser()
        try:
            config.read_file(open('settings.ini'))
        except Exception as e:
            self.logs(e)
        return config

    def extract_sni(self, config):
        sni = config['sni']['server_name']
        return sni

    def get_host(self, config):
        host = config['ssh']['host']
        return host

    def proxy(self, config):
        proxyhost = config['config']['proxyip']
        proxyport = int(config['config']['proxyport'])
        return [proxyhost, proxyport]

    def conn_mode(self, config):
        mode = config['mode']['connection_mode']
        return mode

    def tunneling(self, client, socket):
        connected = True
        while connected:
            r, w, x = select.select([client, socket], [], [client, socket], 3)
            if x:
                connected = False
                break
            for i in r:
                try:
                    data = i.recv(Buffer_length)
                    if not data:
                        connected = False
                        break
                    if i is socket:
                        client.send(data)
                    else:
                        socket.send(data)
                except Exception as e:
                    self.logs(f'{R} {e}{GR}')
                    connected = False
                    break
        client.close()
        socket.close()
        os.system('sudo python3 pidkill.py Disconnect')

    def destination(self, client, address):
        try:
            self.logs(G + '<#> Client {} received!{}'.format(address[-1], GR))
            request = client.recv(9124).decode()
            host = self.get_host(self.conf())
            port = request.split(':')[-1].split()[0]
            try:
                proxip = self.proxy(self.conf())[0]
                proxport = self.proxy(self.conf())[1]
            except ValueError:
                proxip = host
                proxport = port
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((proxip, int(proxport)))
            self.logs(f'{O}[TCP] {G}connected to {proxip}:{proxport}{GR}')
            if int(self.conn_mode(self.conf())) == 2:
                self.secure_connection(client, s)
            elif int(self.conn_mode(self.conf())) == 3:
                self.secure_connection(client, s)
            else:
                injector.connection(self, client, s, str(host), str(port))

            self.tunneling(client, s)
        except Exception as e:
            self.logs(f'{R} {e}{GR}')

    def secure_connection(self, client, s):
        SNI_HOST = self.extract_sni(self.conf())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        s = context.wrap_socket(s, server_hostname=str(SNI_HOST))
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=os.path.relpath(certifi.where()))
        self.logs(f'{O}[TCP] Handshaked successfully to {SNI_HOST}{GR}')
        try:
            self.logs(f'''{O}[TCP] Protocol :{G}{s.version()}\n{O}Ciphersuite :{G} {s.cipher()[0]}\n{O}Peerprincipal:{G} {s.getpeercert()["subject"]}''')
        except:
            self.logs(f'{O}[TCP] Unable to retrieve SSL cert details{GR}')
        client.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    def create_connection(self):
        for res in socket.getaddrinfo(self.localip, self.LISTEN_PORT, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
            af, socktype, proto, canonname, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
            except OSError as msg:
                self.logs(str(msg))
                continue
            try:
                localAddress = socket.gethostbyname("localhost")
                sock.bind((localAddress, self.LISTEN_PORT))
                sock.listen(1)
            except OSError as msg:
                self.logs(str(msg))
                sock.close()
                continue

            self.logs('Waiting for incoming connection to: {}:{}\n'.format(self.localip, self.LISTEN_PORT))
            while True:
                try:
                    client, address = sock.accept()
                    thr = threading.Thread(target=self.destination, args=(client, address))
                    thr.start()
                except:
                    sock.close()
                    break

    def logs(self, log):
        logtime = time.ctime().split()[3]
        logfile = open('logs.txt', 'a')
        logfile.write(f'[{logtime}]: {str(log)}\n')
        logfile.close()

if __name__ == '__main__':
    start = Tun()
    start.create_connection()
