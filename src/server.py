# coroutine support 
import asyncio 
# logging support 
import logging
# default socket 
import socket 

class ServerConfigBuilder : 

    def __init__(self): 
        self.tcp = False 
        self.udp = False 
        self.ip = 'localhost'

    def set_dns(self, dns): 
        self.dns = dns 
        return self 

    def set_port(self, port): 
        self.port = port 
        return self 
    
    def set_ip(self, ip): 
        self.ip = ip 
        return self 
    
    def enable_tcp(self, tcp = True): 
        self.tcp = True 
    
    def enable_udp(self, udp = True): 
        self.udp = udp 
    
    def default(): 
        return ServerConfigBuilder().set_port(8080) 

async def server_main(sc: ServerConfigBuilder): 
    port = sc.port 
    ip = sc.ip 
    logging.info(f'Server start on {ip}:{port}...') 
    s = await asyncio.start_server(serve_single, ip, port) 
    async with s:
        await s.serve_forever() 

async def serve_single \
    (reader: asyncio.StreamReader, writer: asyncio.StreamWriter): 
    logging.info(f'Connection from {writer.get_extra_info("peername")}')
    n = await validate_version_and_method_selection(reader) 
    methods = reader.readexactly(n) 
    if n == 1 and methods[0] == b'\xFF': 
        logging.warning(f'No acceptable method') 
        writer.write(b'\x05\xFF') 
        return
    if await serve_single_impl0(methods, reader, writer): 
        pass 
        while True: 
            (cmd, aytp, addr, port) = validate_request(reader) 
            await handle_request(cmd, aytp, addr, port, reader, writer)
    else: 
        pass 
    
async def serve_single_impl0(methods, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> bool:  
    if b'\x00' in methods: 
        w.write(b'\x05\x00')
        return True 
    return False 

async def validate_version_and_method_selection(reader: asyncio.StreamReader) -> int : 
    twobytes = await reader.readexactly(2) 
    if twobytes[0] != b'\x05': 
        e = f'[Socks5 protocol invalid], version section expected 0x05, but got {twobytes[0]}'
        logging.warning(e)
        raise ValueError() 
    return int (twobytes[1])

async def validate_request(reader: asyncio.StreamReader): 
    [ver, cmd, rsv, aytp] = await reader.readexactly(4) 
    if ver != b'\x05': 
        e = f'[Socks5 protocol invalid], version section expected 0x05, but got {ver}'
        logging.warning(e)
        raise ValueError() 
    if cmd == b'\x01': 
        logging.info('Connect command')
    elif cmd == b'\x02': 
        logging.info('Bind command') 
    elif cmd == b'\x03':
        logging.info('UDP associate command') 
    else: 
        e = f'[Socks5 protocol invalid], command section expected 0x01, 0x02 or 0x03, but got {cmd}'
        logging.warning(e) 
        raise ValueError()  
    if rsv != b'\x00':
        e = f'[Socks5 protocol invalid], reserved section expected 0x00, but got {rsv}'
        logging.warning(e) 
        raise ValueError()
    if aytp == b'\x01': 
        logging.info('IPV4 address') 
    elif aytp == b'\x03': 
        logging.info('Domain name') 
    elif aytp == b'\x04': 
        logging.info('IPV6 address') 
    else: 
        e = f'[Socks5 protocol invalid], address type section expected 0x01, 0x03 or 0x04, but got {aytp}'
        logging.warning(e) 
        raise ValueError() 
    if aytp == b'\x01': 
        addr = await reader.readexactly(4) 
        logging.info(f'IPV4 address: {addr}') 
    elif aytp == b'\x03': 
        len = await reader.readexactly(1) 
        addr = await reader.readexactly(int(len)) 
        nul = await reader.readexactly(1)
        assert nul == b'\x00' 
        logging.info(f'Domain name: {addr}') 
    elif aytp == b'\x04': 
        addr = await reader.readexactly(16) 
        logging.info(f'IPV6 address: {addr}') 
    port = await reader.readexactly(2) 
    return (cmd, aytp, addr, port) 

async def handle_request(cmd, aytp, addr, port, reader: asyncio.StreamReader, writer: asyncio.StreamWriter): 
    if cmd == b'\x01': 
        await handle_connect(aytp, aytp, addr, port, reader, writer) 
    elif cmd == b'\x02': 
        return 
        await handle_bind(aytp, addr, port, reader, writer) 
    elif cmd == b'\x03': 
        return 
        await handle_udp_associate(aytp, addr, port, reader, writer) 
    return 

async def handle_connect(cmd, aytp, addr, port, r: asyncio.StreamReader, w: asyncio.StreamWriter): 
    assert cmd == b'\x01' 
    if aytp == b'\x01': 
        # use four bytes as ip to connect 
        addr2 = socket.inet_ntoa(addr) 
        (reader, writer) = await asyncio.open_connection(addr2, port) 
        sock_name = writer.get_extra_info('sockname') 
        logging.info(f'IPV4 address: {addr2}:{port}') 
        logging.info(f'Local address: {sock_name}')
        w.write(b'\x05\x00\x00\x01' + socket.inet_aton(sock_name[0]) + sock_name[1].to_bytes(2, 'big')) 
        # forward data automatically 
        async def forward(r, w): 
            while True: 
                data = await r.read(1024) 
                if not data: 
                    break 
                w.write(data) 
        await asyncio.gather(forward(r, writer), forward(reader, w)) 
        return 
    pass 

# Actually, never use it, because I'm the server. 
async def validate_reply(reader: asyncio.StreamReader): 
    [ver, rep, rsv, atyp] = await reader.readexactly(4) 
    if ver != b'\x05': 
        e = f'[Socks5 protocol invalid], version section expected 0x05, but got {ver}'
        logging.warning(e)
        raise ValueError() 
    if rep == b'\x00': 
        logging.info('Succeeded') 
    elif rep == b'\x01': 
        logging.info('General SOCKS server failure') 
    elif rep == b'\x02': 
        logging.info('Connection not allowed by ruleset') 
    elif rep == b'\x03': 
        logging.info('Network unreachable') 
    elif rep == b'\x04': 
        logging.info('Host unreachable') 
    elif rep == b'\x05': 
        logging.info('Connection refused') 
    elif rep == b'\x06': 
        logging.info('TTL expired') 
    elif rep == b'\x07': 
        logging.info('Command not supported') 
    elif rep == b'\x08': 
        logging.info('Address type not supported') 
    else: 
        e = f'[Socks5 protocol invalid], reply section expected 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 or 0x08, but got {rep}'
        logging.warning(e)
        raise ValueError() 
    if rsv != b'\x00':
        e = f'[Socks5 protocol invalid], reserved section expected 0x00, but got {rsv}'
        logging.warning(e) 
        raise ValueError()
    if atyp == b'\x01': 
        addr = await reader.readexactly(4) 
        logging.info(f'IPV4 address: {addr}') 
    elif atyp == b'\x03': 
        len = await reader.readexactly(1) 
        addr = await reader.readexactly(int(len)) 
        nul = await reader.readexactly(1)
        assert nul == b'\x00' 
        logging.info(f'Domain name: {addr}') 
    elif atyp == b'\x04': 
        addr = await reader.readexactly(16) 
        logging.info(f'IPV6 address: {addr}') 
    port = await reader.readexactly(2)
    return (rep, atyp, addr, port)

if __name__ == '__main__': 
    logging.getLogger().setLevel(logging.INFO) 
    asyncio.run(server_main(ServerConfigBuilder.default()))