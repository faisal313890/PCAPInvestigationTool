"""Bounded readers for classic PCAP and a documented PCAPNG subset."""
import struct
MAX_BYTES=10*1024*1024
MAX_PACKETS=20000
MAX_FRAME=262144
class CaptureError(ValueError):pass
MAGIC={b'\xd4\xc3\xb2\xa1':('<',1000000),b'\xa1\xb2\xc3\xd4':('>',1000000),
       b'\x4d\x3c\xb2\xa1':('<',1000000000),b'\xa1\xb2\x3c\x4d':('>',1000000000)}

def options(body,endian):
    pos=0;result={}
    while pos<len(body):
        if len(body)-pos<4:raise CaptureError('Incomplete PCAPNG option header.')
        code,length=struct.unpack_from(endian+'HH',body,pos);pos+=4
        if code==0:
            if length:raise CaptureError('Invalid PCAPNG end-of-options length.')
            break
        padded=(length+3)&~3
        if pos+padded>len(body):raise CaptureError('Incomplete PCAPNG option value.')
        result[code]=body[pos:pos+length];pos+=padded
    return result


def read_capture(data):
    if not isinstance(data,bytes) or not 0<len(data)<=MAX_BYTES:raise CaptureError('Choose a nonempty capture up to 10 MiB.')
    packets=[];interfaces=[];errors=[];ignored_blocks=0
    def append(frame,wire,ts,link,interface,note=''):
        if len(packets)>=MAX_PACKETS:raise CaptureError('Capture exceeds the 20,000-packet limit; split it before analysis.')
        packets.append({'number':len(packets)+1,'frame':frame,'wire_length':wire,'captured_length':len(frame),
                        'timestamp_ns':ts,'linktype':link,'interface':interface,'capture_note':note})
    if data[:4] in MAGIC:
        if len(data)<24:raise CaptureError('Incomplete PCAP global header.')
        endian,resolution=MAGIC[data[:4]]
        major,minor,_,_,snap,link=struct.unpack_from(endian+'HHIIII',data,4)
        if (major,minor)!=(2,4) or snap==0:raise CaptureError('Only classic PCAP version 2.4 with a positive snaplen is supported.')
        link&=0xffff;interfaces=[{'id':'pcap:0','linktype':link,'snaplen':snap,'timestamp_units_per_second':resolution}]
        pos=24;fmt='pcap'
        while pos<len(data):
            if len(data)-pos<16:errors.append('Incomplete trailing PCAP packet header.');break
            seconds,frac,cap,wire=struct.unpack_from(endian+'IIII',data,pos);pos+=16
            if cap>wire or cap>snap or cap>MAX_FRAME or frac>=resolution:
                errors.append('Invalid PCAP packet lengths or fractional timestamp. Remaining records were not read.');break
            if pos+cap>len(data):errors.append('Incomplete trailing PCAP packet data.');break
            append(data[pos:pos+cap],wire,seconds*1000000000+frac*1000000000//resolution,link,'pcap:0');pos+=cap
    elif data[:4]==b'\x0a\x0d\x0d\x0a':
        pos=0;endian=None;local=[];section=0;fmt='pcapng'
        while pos<len(data):
            try:
                if len(data)-pos<12:raise CaptureError('Incomplete trailing PCAPNG block.')
                shb=data[pos:pos+4]==b'\x0a\x0d\x0d\x0a'
                if shb:
                    if len(data)-pos<28:raise CaptureError('Incomplete PCAPNG section header.')
                    bom=data[pos+8:pos+12]
                    endian='<' if bom==b'\x4d\x3c\x2b\x1a' else '>' if bom==b'\x1a\x2b\x3c\x4d' else None
                    if not endian:raise CaptureError('Invalid PCAPNG byte-order magic.')
                if endian is None:raise CaptureError('PCAPNG block has no section byte order.')
                kind,length=struct.unpack_from(endian+'II',data,pos)
                if length<12 or length%4 or pos+length>len(data):raise CaptureError('Invalid or incomplete PCAPNG block length.')
                if struct.unpack_from(endian+'I',data,pos+length-4)[0]!=length:raise CaptureError('PCAPNG block trailer length mismatch.')
                body=data[pos+8:pos+length-4]
                if shb:
                    if len(body)<16 or struct.unpack_from(endian+'HH',body,4)!=(1,0):raise CaptureError('Only PCAPNG section version 1.0 is supported.')
                    section+=1;local=[]
                elif kind==1:
                    if len(body)<8:raise CaptureError('Incomplete interface description.')
                    link,_,snap=struct.unpack_from(endian+'HHI',body)
                    opts=options(body[8:],endian)
                    value=opts.get(9,b'\x06')
                    if len(value)!=1:raise CaptureError('Invalid timestamp-resolution option.')
                    unit=(2**(value[0]&127)) if value[0]&128 else 10**value[0]
                    offset=opts.get(14,b'\0'*8)
                    if len(offset)!=8:raise CaptureError('Invalid timestamp-offset option.')
                    item={'id':f'section{section}:if{len(local)}','linktype':link,'snaplen':snap,
                          'timestamp_units_per_second':unit,'timestamp_offset_seconds':struct.unpack(endian+'q',offset)[0]}
                    local.append(item);interfaces.append(dict(item))
                elif kind==6:
                    if len(body)<20:raise CaptureError('Incomplete enhanced packet block.')
                    iface,high,low,cap,wire=struct.unpack_from(endian+'IIIII',body)
                    if iface>=len(local):raise CaptureError('Packet references an unknown interface.')
                    info=local[iface]
                    if cap>wire or cap>MAX_FRAME or (info['snaplen'] and cap>info['snaplen']) or 20+((cap+3)&~3)>len(body):raise CaptureError('Invalid enhanced packet data length.')
                    options(body[20+((cap+3)&~3):],endian)
                    ns=((high<<32)|low)*1000000000//info['timestamp_units_per_second']+info['timestamp_offset_seconds']*1000000000
                    append(body[20:20+cap],wire,ns,info['linktype'],info['id'])
                elif kind==3:
                    if len(body)<4 or not local:raise CaptureError('Simple packet block lacks interface or length.')
                    info=local[0];wire=struct.unpack_from(endian+'I',body)[0];cap=min(wire,info['snaplen']) if info['snaplen'] else wire
                    if cap>MAX_FRAME or 4+((cap+3)&~3)!=len(body):raise CaptureError('Invalid simple packet block data length.')
                    append(body[4:4+cap],wire,None,info['linktype'],info['id'],'Simple Packet Block has no timestamp; excluded from time-window rules.')
                elif kind==2:
                    append(b'',0,None,-1,f'section{section}:unknown','Obsolete Packet Block is unsupported; packet metadata was not decoded.')
                else:ignored_blocks+=1
                pos+=length
            except CaptureError as exc:
                if '20,000' in str(exc):raise
                errors.append(str(exc)+' Remaining blocks were not read.');break
    else:raise CaptureError('Unrecognized capture signature. Upload classic PCAP or supported PCAPNG, not ZIP or text.')
    if errors and not packets:raise CaptureError(errors[0])
    return packets,{'format':fmt,'interfaces':interfaces,'capture_errors':errors,'ignored_metadata_blocks':ignored_blocks}
