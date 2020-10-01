import logging
import socket
import struct
import select
import threading
import hashlib
from arc4 import ARC4

logging.basicConfig(level=logging.DEBUG)
def send_data(sock, data):
    # print(data)
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent

def handle_tcp(decode_arc4, sock, remote):
    # 处理 client socket 和 remote socket 的数据流
    
    encode_rc4 = ARC4('niceDayIn2020@998')
    try:
        fdset = [sock, remote]
        while True:
            # 用 IO 多路复用 select 监听套接字是否有数据流
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                data = sock.recv(4096)
                if len(data) <= 0:
                    break
                rdata = decode_arc4.decrypt(data)
                print(rdata)
                result = send_data(remote, rdata)
                if result < len(data):
                    raise Exception('failed to send all data')

            if remote in r:
                data = remote.recv(4096)
                if len(data) <= 0:
                    break
                result = send_data(sock, encode_rc4.encrypt(data))
                if result < len(data):
                    raise Exception('failed to send all data')
    except Exception as e:
        raise(e)
    finally:
        sock.close()
        remote.close()

def handle_con(sock, addr):
    # 活动目标地址和端口
    datalen = struct.unpack('>B', sock.recv(1))[0]
    logging.info('datalen %d' % (datalen))
    encode_data = sock.recv(datalen)
    decode_arc4 = ARC4('niceDayIn2020@998')
    data = decode_arc4.decrypt(encode_data)
    print(data)

    addrLen = struct.unpack('>H', data[0:2])[0]
    logging.info('addrLen %d' % (addrLen))
    target_addr = data[2:addrLen + 2]
    logging.info('target_addr %s' % (target_addr))

    target_port = struct.unpack('>H', data[2 + addrLen:addrLen + 4])[0]
    logging.info('target_port %d' % (target_port))


    addrMd5 = data[4 + addrLen:4 + addrLen + 32]
    logging.info('addrMd5 %s' % (addrMd5))

    md5 = hashlib.md5()
    md5.update(target_addr)
    _addrMd5 = md5.hexdigest()
    logging.info('_addrMd5 %s' % (_addrMd5))
    if addrMd5.decode("utf-8")  != _addrMd5:
      print(target_addr)
      print('addr error')
      sock.close()
      return
    print('addr right')
    # logging.info('data length %d' % (datalen[0]))
    # target_addr = sock.recv(datalen[0])
    # logging.info('target_addr %s' % (target_addr))
    # target_port = struct.unpack('>H', sock.recv(2))
    # logging.info('target_port %s' % (target_port))
    # 拿到 remote address 的信息后，建立连接
    try:
        remote = socket.create_connection((target_addr, target_port))
        logging.info('connecting %s:%d' % (target_addr, target_port))
    except socket.error as e:
        logging.error(e)
        return

    handle_tcp(decode_arc4, sock, remote)
def main():
    socketServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    socketServer.bind(('', 16801))
    socketServer.listen(5)
    logging.info('remoteserver listen %d' % (16801))
    try:
        while True:
            sock, addr = socketServer.accept()
            logging.info(addr)
            t = threading.Thread(target=handle_con, args=(sock, addr))
            t.start()
    except socket.error as e:
        logging.error(e)
    except KeyboardInterrupt:
        socketServer.close()


if __name__ == '__main__':
    main()