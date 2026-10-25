"""Write synthetic capture files only; no sockets, packet sending or live capture."""
import ipaddress,struct
from pathlib import Path
BASE_SECONDS=1792922400  # 2026-10-25T10:00:00Z

def checksum(data):
    if len(data)%2:data+=b'\0'
    n=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while n>>16:n=(n&65535)+(n>>16)
    return (~n)&65535

def ip4(src,dst,proto,payload,fragment=0):
    a,b=ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed
    h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),1,fragment,64,proto,0,a,b)
    return h[:10]+struct.pack('!H',checksum(h))+h[12:]+payload

def tcp(src,dst,sport,dport,flags=2,payload=b''):
    seg=struct.pack('!HHIIBBHHH',sport,dport,100,100,0x50,flags,64240,0,0)+payload
    pseudo=ipaddress.ip_address(src).packed+ipaddress.ip_address(dst).packed+struct.pack('!BBH',0,6,len(seg))
    seg=seg[:16]+struct.pack('!H',checksum(pseudo+seg))+seg[18:]
    return ethernet(ip4(src,dst,6,seg))

def udp(src,dst,sport,dport,payload):
    seg=struct.pack('!HHHH',sport,dport,8+len(payload),0)+payload
    pseudo=ipaddress.ip_address(src).packed+ipaddress.ip_address(dst).packed+struct.pack('!BBH',0,17,len(seg))
    value=checksum(pseudo+seg) or 65535
    seg=seg[:6]+struct.pack('!H',value)+seg[8:]
    return ethernet(ip4(src,dst,17,seg))

def dns_message(name='service.example.test',response=False,rcode=0):
    labels=b''.join(bytes([len(p)])+p.encode('ascii') for p in name.split('.'))+b'\0'
    return struct.pack('!6H',42,(0x8180 if response else 0x0100)|rcode,1,0,0,0)+labels+struct.pack('!HH',1,1)

def ethernet(payload,etype=0x0800):return bytes.fromhex('020000000002020000000001')+struct.pack('!H',etype)+payload

def pcap(records,endian='<',nano=False,linktype=1):
    magic=0xa1b23c4d if nano else 0xa1b2c3d4
    result=struct.pack(endian+'IHHIIII',magic,2,4,0,0,65535,linktype)
    for i,entry in enumerate(records):
        if isinstance(entry,tuple):frame,offset,wire=entry
        else:frame,offset,wire=entry,i,len(entry)
        seconds=BASE_SECONDS+int(offset);frac=round((offset-int(offset))*(1000000000 if nano else 1000000))
        result+=struct.pack(endian+'IIII',seconds,frac,len(frame),wire)+frame
    return result

def block(kind,body,endian='<'):
    body+=b'\0'*((-len(body))%4);length=len(body)+12
    return struct.pack(endian+'II',kind,length)+body+struct.pack(endian+'I',length)

def pcapng(records,endian='<',tsresol=6,offset=0,linktype=1,simple=False):
    out=block(0x0a0d0d0a,struct.pack(endian+'IHHq',0x1a2b3c4d,1,0,-1),endian)
    opts=struct.pack(endian+'HH',9,1)+bytes([tsresol])+b'\0'*3
    opts+=struct.pack(endian+'HHq',14,8,offset)+b'\0'*4
    out+=block(1,struct.pack(endian+'HHI',linktype,0,65535)+opts,endian)
    units=2**(tsresol&127) if tsresol&128 else 10**tsresol
    for i,frame in enumerate(records):
        if simple:out+=block(3,struct.pack(endian+'I',len(frame))+frame,endian)
        else:
            ts=(BASE_SECONDS+i-offset)*units
            out+=block(6,struct.pack(endian+'5I',0,ts>>32,ts&0xffffffff,len(frame),len(frame))+frame,endian)
    return out

def samples():
    client,resolver,web='192.0.2.10','198.51.100.53','203.0.113.10'
    normal=[udp(client,resolver,53000,53,dns_message()),udp(resolver,client,53,53000,dns_message(response=True)),
            tcp(client,web,51000,443,2),tcp(web,client,443,51000,0x12),tcp(client,web,51000,443,0x10),tcp(web,client,443,51000,0x10)]
    suspicious=[tcp('192.0.2.66','203.0.113.20',52000,p) for p in range(20,32)]
    suspicious += [udp(resolver,'192.0.2.66',53,53000,dns_message(f'missing{i}.example.test',True,3)) for i in range(6)]
    suspicious += [udp('192.0.2.66',resolver,53000,53,dns_message('a'*55+'.example.test'))]
    plaintext=[tcp(client,web,51001,80,0x18,b'GET /account?token=DO_NOT_EXPORT HTTP/1.1\r\nHost: service.example.test\r\nAuthorization: Bearer DEMO_ONLY_NOT_SECRET\r\n\r\n')]
    return {'normal.pcap':pcap(normal),'normal.pcapng':pcapng(normal),'suspicious.pcap':pcap(suspicious),
            'plaintext.pcap':pcap(plaintext),'partial.pcap':pcap(normal+[(b'\0'*10,7,60)])}

if __name__=='__main__':
    root=Path(__file__).resolve().parent/'examples';root.mkdir(exist_ok=True)
    for name,data in samples().items():(root/name).write_bytes(data)
    print('Synthetic sample files written. No packets were transmitted.')
