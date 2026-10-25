"""Offline packet metadata, directional flow summaries and review patterns."""
import argparse,csv,hashlib,io,ipaddress,json,re,struct,unicodedata,uuid
from collections import Counter,defaultdict
from datetime import datetime,timedelta,timezone
from pathlib import Path
from capture import read_capture,CaptureError,MAX_BYTES
VERSION='0.1.0'
LIMITATIONS=[
 'Review patterns are not proof of scanning, malware, DNS tunneling, exfiltration, or compromise. Legitimate diagnostics, typos, CDNs, monitoring and retransmissions can produce similar observations.',
 'Only documented frame and packet metadata is decoded. No checksum verification, TCP session reconstruction, stream/IP-fragment reassembly, decryption, file extraction, host access, live capture or packet transmission is performed.',
 'Flows are directional interface/IP/protocol/port groups, not authenticated connections or unique TCP sessions. Capture bytes are not application payload volume; wire lengths are unverified capture metadata.',
 'DNS inspection covers UDP port 53 headers and up to 16 questions per packet, not answer records, EDNS extended response codes, TCP DNS, DoH or DoT. Questions and response codes are not authenticated or correlated into transactions.',
 'IPv6 base headers with direct TCP/UDP/ICMPv6 are supported; extension headers, IP fragments, Wi-Fi, loopback and unknown linktypes are reported as incomplete rather than silently treated as decoded.',
 'Threshold rules use timed packets only. Capture order is retained for frame references; window checks sort by recorded time. Missing interfaces, clock errors, packet loss, timestamps and duplicate/mirrored captures are not repaired or deduplicated.',
 'No raw packet payloads, HTTP paths, headers, credentials or bodies are exported. IPs, ports, DNS question names, capture filenames and timestamps can still be sensitive. Review before sharing.',
 'Preview: at most 200 packets; flows: 500; DNS rows: 200; alerts: 200; diagnostics: 50. Full aggregate and omitted-detail counts are reported. No alerts does not establish safety or complete traffic coverage.',
]

def visible(value):return ''.join(f'\\u{ord(c):04x}' if unicodedata.category(c) in {'Cc','Cf','Cs'} else c for c in str(value))
def iso(ns):
    if ns is None:return None
    try:
        sec,frac=divmod(ns,1000000000)
        dt=datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(seconds=sec)
        return f'{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}.{frac:09d}Z'
    except (OverflowError,ValueError):return None


def dns_name(data,pos):
    labels=[];seen=set();end=None;wire=1
    for _ in range(128):
        if pos>=len(data) or pos in seen:raise ValueError('Invalid or cyclic DNS name.')
        seen.add(pos);length=data[pos]
        if length&0xc0==0xc0:
            if pos+1>=len(data):raise ValueError('Incomplete DNS pointer.')
            pointer=((length&63)<<8)|data[pos+1]
            if pointer>=pos:raise ValueError('DNS compression pointer is not backward.')
            if end is None:end=pos+2
            pos=pointer;continue
        if length&0xc0:raise ValueError('Unsupported DNS label type.')
        pos+=1
        if not length:return labels,end if end is not None else pos
        if length>63 or pos+length>len(data):raise ValueError('Incomplete DNS label.')
        wire+=length+1
        if wire>255:raise ValueError('DNS name exceeds 255 wire bytes.')
        labels.append(data[pos:pos+length]);pos+=length
    raise ValueError('DNS name step limit exceeded.')


def dns(data):
    if len(data)<12:raise ValueError('Incomplete DNS header.')
    _,flags,qd,_,_,_=struct.unpack_from('!6H',data)
    if qd>16:raise ValueError('DNS question count exceeds the supported limit of 16.')
    questions=[];pos=12
    for _ in range(qd):
        labels,pos=dns_name(data,pos)
        if pos+4>len(data):raise ValueError('Incomplete DNS question.')
        qtype,qclass=struct.unpack_from('!HH',data,pos);pos+=4
        parts=[''.join(chr(b) if 33<=b<=126 and b not in (46,92) else f'\\x{b:02x}' for b in label) for label in labels]
        questions.append({'name':'.'.join(parts) if parts else '(root)','type':qtype,'class':qclass,
                          'max_label_bytes':max(map(len,labels),default=0),'name_wire_bytes':sum(len(x)+1 for x in labels)+1})
    return {'response':bool(flags&0x8000),'rcode':flags&15,'questions':questions}


def decode(record):
    raw=record['frame'];link=record['linktype'];issues=[]
    item={k:v for k,v in record.items() if k!='frame'}
    item.update(timestamp_utc=iso(record['timestamp_ns']),source_ip=None,destination_ip=None,source_port=None,destination_port=None,
                protocol='OTHER',tcp_flags=None,dns=None,http_method=None)
    if record['capture_note']:issues.append(record['capture_note'])
    if item['timestamp_utc'] is None:
        item['timestamp_ns']=None
        if not record['capture_note']:issues.append('Timestamp is outside the supported UTC display range or missing.')
    if len(raw)<record['wire_length']:issues.append('Capture record is snaplen-truncated relative to original length.')
    try:
        if link==1:
            if len(raw)<14:raise ValueError('Incomplete Ethernet header.')
            etype=struct.unpack_from('!H',raw,12)[0];pos=14
            for _ in range(4):
                if etype not in {0x8100,0x88a8}:break
                if pos+4>len(raw):raise ValueError('Incomplete VLAN header.')
                etype=struct.unpack_from('!H',raw,pos+2)[0];pos+=4
            if etype in {0x8100,0x88a8}:raise ValueError('VLAN nesting exceeds supported limit.')
            payload=raw[pos:]
        elif link==113:
            if len(raw)<16:raise ValueError('Incomplete Linux cooked header.')
            etype=struct.unpack_from('!H',raw,14)[0];payload=raw[16:]
        elif link==276:
            if len(raw)<20:raise ValueError('Incomplete Linux cooked v2 header.')
            etype=struct.unpack_from('!H',raw)[0];payload=raw[20:]
        elif link in {101,228,229}:
            if not raw:raise ValueError('Empty raw-IP frame.')
            version=raw[0]>>4
            if (link==228 and version!=4) or (link==229 and version!=6):raise ValueError('Raw linktype and IP version disagree.')
            etype=0x0800 if version==4 else 0x86dd if version==6 else 0
            payload=raw
        else:raise ValueError(f'Unsupported linktype {link}.')
        if etype==0x0806:
            if len(payload)<8:raise ValueError('Incomplete ARP header.')
            item['protocol']='ARP';return item,issues
        if etype==0x0800:
            if len(payload)<20 or payload[0]>>4!=4:raise ValueError('Incomplete or invalid IPv4 header.')
            ihl=(payload[0]&15)*4;total=struct.unpack_from('!H',payload,2)[0]
            if ihl<20 or ihl>len(payload) or total<ihl:raise ValueError('Invalid IPv4 length fields.')
            item['source_ip']=str(ipaddress.ip_address(payload[12:16]));item['destination_ip']=str(ipaddress.ip_address(payload[16:20]))
            proto=payload[9];item['protocol']={6:'TCP',17:'UDP',1:'ICMP'}.get(proto,f'IPPROTO-{proto}')
            if total>len(payload):raise ValueError('IPv4 data is incomplete; transport metadata was not decoded.')
            if struct.unpack_from('!H',payload,6)[0]&0x3fff:raise ValueError('IPv4 fragment: transport decoding and reassembly not performed.')
            transport=payload[ihl:total]
        elif etype==0x86dd:
            if len(payload)<40 or payload[0]>>4!=6:raise ValueError('Incomplete or invalid IPv6 base header.')
            length=struct.unpack_from('!H',payload,4)[0];proto=payload[6]
            item['source_ip']=str(ipaddress.ip_address(payload[8:24]));item['destination_ip']=str(ipaddress.ip_address(payload[24:40]))
            item['protocol']={6:'TCP',17:'UDP',58:'ICMPv6'}.get(proto,f'IPPROTO-{proto}')
            if 40+length>len(payload):raise ValueError('IPv6 data is incomplete.')
            if proto in {0,43,44,50,51,60,135}:raise ValueError('IPv6 extension/fragment headers are outside this decoder profile.')
            transport=payload[40:40+length]
        else:raise ValueError(f'Unsupported Ethernet/network type 0x{etype:04x}.')
        if proto==6:
            if len(transport)<20:raise ValueError('Incomplete TCP header.')
            off=(transport[12]>>4)*4
            if off<20 or off>len(transport):raise ValueError('Invalid TCP data offset.')
            item['source_port'],item['destination_port']=struct.unpack_from('!HH',transport)
            item['tcp_flags']=transport[13]
            # Recognize only a complete first HTTP/1.x request line within this packet.
            match=re.match(rb'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) [^\r\n]{1,4096} HTTP/1\.[01]\r\n',transport[off:])
            if match:item['http_method']=match[1].decode('ascii')
        elif proto==17:
            if len(transport)<8:raise ValueError('Incomplete UDP header.')
            sport,dport,length,_=struct.unpack_from('!HHHH',transport)
            if length<8 or length>len(transport):raise ValueError('Invalid/incomplete UDP datagram length.')
            item['source_port'],item['destination_port']=sport,dport
            if sport==53 or dport==53:
                try:item['dns']=dns(transport[8:length])
                except ValueError as exc:issues.append(str(exc))
        elif proto in {1,58}:
            if len(transport)<4:raise ValueError('Incomplete ICMP header.')
        elif proto!=59:issues.append('IP protocol is outside the transport decoder profile.')
    except (ValueError,struct.error) as exc:issues.append(str(exc))
    return item,issues


def window_peak(items,seconds,key=None):
    items=sorted(items,key=lambda p:(p['timestamp_ns'],p['number']));left=0;counts=Counter();best=(-1,0,0)
    for right,p in enumerate(items):
        if key:counts[p[key]]+=1
        while p['timestamp_ns']-items[left]['timestamp_ns']>seconds*1000000000:
            if key:
                val=items[left][key];counts[val]-=1
                if not counts[val]:del counts[val]
            left+=1
        metric=len(counts) if key else right-left+1
        if metric>best[0]:best=(metric,left,right+1)
    return best[0],items[best[1]:best[2]]


def patterns(packets,port_threshold):
    syn=defaultdict(list);negative=defaultdict(list);long=defaultdict(list);http=defaultdict(list)
    for p in packets:
        scope=(p['interface'],p['source_ip'],p['destination_ip'])
        if p['timestamp_ns'] is not None:
            if p['protocol']=='TCP' and p['tcp_flags'] is not None and p['tcp_flags']&2 and not p['tcp_flags']&16:syn[scope].append(p)
            if p['dns'] and p['dns']['response'] and p['dns']['rcode']==3:negative[scope].append(p)
        if p['dns'] and not p['dns']['response'] and any(q['max_label_bytes']>=50 or q['name_wire_bytes']>=180 for q in p['dns']['questions']):long[scope].append(p)
        if p['http_method']:http[scope].append(p)
    alerts=[]
    def add(rule,title,scope,items,metric,threshold,meaning,window=None,priority='review'):
        times=sorted(p['timestamp_ns'] for p in items if p['timestamp_ns'] is not None)
        alerts.append({'rule':rule,'title':title,'priority':priority,'scope':dict(zip(('interface','source_ip','destination_ip'),scope)),
         'observed_metric':metric,'threshold':threshold,'window_seconds':window,'packet_count':len(items),
         'frame_numbers':[p['number'] for p in items[:20]],'frame_references_truncated':len(items)>20,
         'first_utc':iso(times[0]) if times else None,'last_utc':iso(times[-1]) if times else None,
         'meaning':meaning,'suggested_action':'Check capture completeness, expected applications and administrative activity. Correlate with endpoint/application logs before drawing an incident conclusion.'})
    for scope,items in syn.items():
        count,peak=window_peak(items,60,'destination_port')
        if count>=port_threshold:add('PCI-001','Many TCP SYN destination ports',scope,peak,count,port_threshold,
          'SYN packets without ACK reached the distinct-port threshold for one destination. This can resemble probing, but no successful connection or malicious scan was established.',60)
    for scope,items in negative.items():
        count,peak=window_peak(items,60)
        if count>=5:add('PCI-002','Repeated DNS NXDOMAIN response codes',scope,peak,count,5,
          'UDP DNS responses with low-four-bit RCODE 3 reached the threshold. Typos, software retries and misconfiguration are possible; DNS answers and transaction authenticity were not verified.',60)
    for scope,items in long.items():add('PCI-003','Long DNS question names or labels',scope,items,len(items),1,
       'At least one question has a label of 50+ bytes or a name of 180+ wire bytes. This is a lexical observation; CDN/service names and other legitimate uses can be long. Tunneling or exfiltration was not established.')
    for scope,items in http.items():add('PCI-004','Visible HTTP/1.x request markers',scope,items,len(items),1,
       'Complete HTTP/1.x request-line markers were observed in individual TCP packets. HTTP paths, headers and bodies are withheld. This is a plaintext-protocol observation, not proof of sensitive data exposure.',priority='info')
    alerts.sort(key=lambda a:(a['first_utc'] or '',a['rule'],str(a['scope'])))
    for i,a in enumerate(alerts,1):a['id']=f'OBS-{i:04d}'
    return alerts


def analyze(data,filename='uploaded.pcap',port_threshold=10):
    if type(port_threshold) is not int or not 3<=port_threshold<=100:raise CaptureError('Port threshold must be 3–100 distinct destination ports.')
    raw,metadata=read_capture(data);packets=[];diagnostics=[];affected=0;all_issues=Counter()
    for record in raw:
        item,issues=decode(record);item['issues']=issues;packets.append(item)
        if issues:
            affected+=1;all_issues.update(issues)
            if len(diagnostics)<50:diagnostics.append({'frame':item['number'],'issues':issues})
    ip_packets=[p for p in packets if p['source_ip'] is not None]
    flows={};dns_counts=Counter();dns_examples={}
    for p in ip_packets:
        key=(p['interface'],p['source_ip'],p['destination_ip'],p['protocol'],p['source_port'],p['destination_port'])
        if key not in flows:flows[key]={'interface':key[0],'source_ip':key[1],'destination_ip':key[2],'protocol':key[3],
          'source_port':key[4],'destination_port':key[5],'packets':0,'captured_bytes':0,'wire_bytes_reported':0,'first_utc':None,'last_utc':None,'frame_examples':[]}
        row=flows[key];row['packets']+=1;row['captured_bytes']+=p['captured_length'];row['wire_bytes_reported']+=p['wire_length']
        if p['timestamp_utc']:
            row['first_utc']=min(row['first_utc'] or p['timestamp_utc'],p['timestamp_utc']);row['last_utc']=max(row['last_utc'] or p['timestamp_utc'],p['timestamp_utc'])
        if len(row['frame_examples'])<10:row['frame_examples'].append(p['number'])
        if p['dns']:
            for q in p['dns']['questions']:
                key=(p['interface'],p['source_ip'],p['destination_ip'],q['name'],q['type'],p['dns']['response'],p['dns']['rcode'])
                dns_counts[key]+=1;dns_examples.setdefault(key,p['number'])
    flow_rows=sorted(flows.values(),key=lambda x:(-x['packets'],str(x)))
    dns_rows=[dict(zip(('interface','source_ip','destination_ip','question_name','question_type','is_response','rcode'),k),packets=n,example_frame=dns_examples[k]) for k,n in dns_counts.most_common()]
    alerts=patterns(packets,port_threshold)
    timed=[p['timestamp_ns'] for p in packets if p['timestamp_ns'] is not None]
    warnings=list(metadata['capture_errors'])
    if affected:warnings.append(f'{affected} packet records have incomplete metadata or coverage issues. Review diagnostics; unobserved fields were not assumed safe.')
    if timed!=sorted(timed):warnings.append('Capture timestamps are out of order. Time-window rules sort recorded timestamps; capture frame references retain file order.')
    status='no_packets' if not packets else 'partial' if affected or metadata['capture_errors'] else 'decoded_profile'
    preview=[]
    for p in packets[:200]:
        row={k:v for k,v in p.items() if k not in {'timestamp_ns','dns'}}
        row['dns_questions']=[q['name'] for q in p['dns']['questions']] if p['dns'] else []
        preview.append(row)
    return {'tool':'PCAP Investigation Tool','version':VERSION,'report_id':str(uuid.uuid4()),'analyzed_at_utc':datetime.now(timezone.utc).isoformat(),
      'source_file':visible(str(filename).replace('\\','/').split('/')[-1][:255]),'input_sha256':hashlib.sha256(data).hexdigest(),
      'parse_status':status,'capture':metadata,'settings':{'distinct_syn_ports':port_threshold,'syn_window_seconds':60,'nxdomain_responses':5,'nxdomain_window_seconds':60,'long_label_bytes':50,'long_name_wire_bytes':180},
      'summary':{'packet_records':len(packets),'ip_packets':len(ip_packets),'directional_flows':len(flow_rows),
       'dns_packets':sum(p['dns'] is not None for p in packets),'dns_queries':sum(bool(p['dns'] and not p['dns']['response']) for p in packets),
       'dns_responses':sum(bool(p['dns'] and p['dns']['response']) for p in packets),'review_alerts':sum(a['priority']=='review' for a in alerts),
       'informational_observations':sum(a['priority']=='info' for a in alerts),'packets_with_issues':affected,
       'untimed_packets':len(packets)-len(timed),'capture_truncated_packets':sum(p['captured_length']<p['wire_length'] for p in packets),
       'captured_bytes':sum(p['captured_length'] for p in packets),'wire_bytes_reported':sum(p['wire_length'] for p in packets),
       'protocols':dict(Counter(p['protocol'] for p in packets))},
      'time_range_utc':{'first':iso(min(timed)) if timed else None,'last':iso(max(timed)) if timed else None},
      'alerts':alerts[:200],'alert_counts':dict(Counter(a['rule'] for a in alerts)),
      'flows':flow_rows[:500],'dns_questions':dns_rows[:200],'packet_preview':preview,
      'omitted_details':{'flows':max(0,len(flow_rows)-500),'dns_rows':max(0,len(dns_rows)-200),'packets':max(0,len(packets)-200),'alerts':max(0,len(alerts)-200),'packet_diagnostics':max(0,affected-50)},
      'diagnostics':diagnostics,'issue_counts':dict(all_issues),'warnings':warnings,'limitations':LIMITATIONS}


def csv_safe(value):
    value=str(value)
    return "'"+value if value.lstrip().startswith(('=','+','-','@')) or value.startswith(('\t','\r','\n')) else value

def to_csv(report):
    out=io.StringIO(newline='');w=csv.writer(out)
    fields=['interface','source_ip','source_port','destination_ip','destination_port','protocol','packets','captured_bytes','wire_bytes_reported','first_utc','last_utc']
    w.writerow(fields)
    for row in report['flows']:w.writerow([csv_safe(row[k] if row[k] is not None else '') for k in fields])
    return out.getvalue()


def main():
    p=argparse.ArgumentParser(description='Investigate saved packet captures offline.')
    p.add_argument('file',type=Path);p.add_argument('--port-threshold',type=int,default=10);p.add_argument('--out',type=Path);p.add_argument('--csv',type=Path)
    a=p.parse_args()
    try:
        if a.file.stat().st_size>MAX_BYTES:raise CaptureError('Capture exceeds 10 MiB.')
        r=analyze(a.file.read_bytes(),a.file.name,a.port_threshold)
        for path,text in ((a.out,json.dumps(r,indent=2)),(a.csv,to_csv(r))):
            if path:path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text,encoding='utf-8')
    except (ValueError,OSError) as exc:p.exit(2,str(exc)+'\n')
    print(r['parse_status'],json.dumps(r['summary']))
    for a in r['alerts']:print(a['id'],a['rule'],a['title'],json.dumps(a['scope']))
    return 0 if r['parse_status']=='decoded_profile' else 1
if __name__=='__main__':raise SystemExit(main())
