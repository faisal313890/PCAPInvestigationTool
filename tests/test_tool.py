import base64,csv,io,json,struct,threading,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from capture import read_capture,CaptureError
from analyzer import analyze,dns,dns_name,to_csv,csv_safe
from sample_builder import pcap,pcapng,tcp,udp,dns_message,ethernet,ip4,block,BASE_SECONDS
from server import Handler
ROOT=Path(__file__).resolve().parent.parent

def fixture(name):return (ROOT/'examples'/name).read_bytes()
def syns(n=10,flags=2):return [tcp('192.0.2.1','203.0.113.1',50000,20+i,flags) for i in range(n)]

class ContainerTests(unittest.TestCase):
    def test_normal_classic_fixture(self):
        r=analyze(fixture('normal.pcap'));self.assertEqual(r['parse_status'],'decoded_profile')
        self.assertEqual(r['summary']['packet_records'],6);self.assertEqual(r['summary']['directional_flows'],4)
    def test_normal_pcapng_same_metadata(self):
        a=analyze(fixture('normal.pcap'));b=analyze(fixture('normal.pcapng'))
        self.assertEqual(a['summary'],b['summary']);self.assertEqual(a['time_range_utc'],b['time_range_utc'])
    def test_classic_endian_and_nanosecond_magic(self):
        for endian in ('<','>'):
            for nano in (False,True):
                data=pcap([(syns(1)[0],0.25,len(syns(1)[0]))],endian,nano)
                records,_=read_capture(data)
                self.assertEqual(records[0]['timestamp_ns'],BASE_SECONDS*1000000000+250000000)
                self.assertEqual(analyze(data)['summary']['ip_packets'],1)
    def test_pcapng_endian_binary_resolution_offset(self):
        for endian in ('<','>'):
            r=analyze(pcapng(syns(1),endian,0x8a,3600))
            self.assertEqual(r['parse_status'],'decoded_profile')
            self.assertEqual(r['time_range_utc']['first'],analyze(pcap(syns(1)))['time_range_utc']['first'])
    def test_simple_packet_block_has_no_invented_time(self):
        r=analyze(pcapng(syns(12),simple=True));self.assertEqual(r['summary']['untimed_packets'],12)
        self.assertNotIn('PCI-001',r['alert_counts']);self.assertEqual(r['parse_status'],'partial')
    def test_multiple_sections_keep_interfaces_separate(self):
        r=analyze(pcapng(syns(6))+pcapng(syns(6)))
        self.assertEqual(len(r['capture']['interfaces']),2);self.assertEqual(r['summary']['directional_flows'],12)
        self.assertNotIn('PCI-001',r['alert_counts'])
    def test_unknown_interface_is_capture_error(self):
        # Explicit enhanced block references interface 99 without a matching IDB.
        data=pcapng([])
        data+=block(6,struct.pack('<5I',99,0,0,0,0))
        with self.assertRaises(CaptureError):analyze(data)
    def test_interfaces_do_not_combine_port_windows(self):
        data=pcapng(syns(6))
        data+=block(1,struct.pack('<HHI',1,0,65535))
        for i in range(6):
            frame=tcp('192.0.2.1','203.0.113.1',50000,26+i)
            ts=(BASE_SECONDS+i)*1000000
            data+=block(6,struct.pack('<5I',1,ts>>32,ts&0xffffffff,len(frame),len(frame))+frame)
        r=analyze(data)
        self.assertEqual(r['summary']['packet_records'],12)
        self.assertNotIn('PCI-001',r['alert_counts'])
    def test_bad_block_trailer_rejected(self):
        data=bytearray(pcapng([]));data[-4:]=b'\x00'*4
        with self.assertRaises(CaptureError):analyze(bytes(data))
    def test_truncated_trailing_record_keeps_partial_prefix(self):
        r=analyze(fixture('normal.pcap')+b'\x01\x02')
        self.assertEqual(r['summary']['packet_records'],6);self.assertEqual(r['parse_status'],'partial');self.assertTrue(r['capture']['capture_errors'])
    def test_invalid_classic_cap_length_no_fabricated_packet(self):
        data=pcap([])+struct.pack('<IIII',BASE_SECONDS,0,100,1)+b'abc'
        with self.assertRaises(CaptureError):analyze(data)
    def test_unknown_and_oversized_files_rejected(self):
        for data in (b'',b'not pcap',b'PK\x03\x04',b'x'*(10*1024*1024+1)):
            with self.assertRaises(CaptureError):analyze(data)
    def test_record_limit_enforced(self):
        data=pcap([b'']*4)
        with patch('capture.MAX_PACKETS',3):
            with self.assertRaises(CaptureError):analyze(data)

class ProtocolTests(unittest.TestCase):
    def test_unsupported_linktype_is_visible(self):
        r=analyze(pcap(syns(1),linktype=105));self.assertEqual(r['parse_status'],'partial')
        self.assertEqual(r['summary']['ip_packets'],0);self.assertIn('Unsupported linktype',str(r['diagnostics']))
    def test_raw_ipv4_and_link_mismatch(self):
        frame=syns(1)[0][14:];self.assertEqual(analyze(pcap([frame],linktype=101))['summary']['ip_packets'],1)
        self.assertEqual(analyze(pcap([frame],linktype=229))['summary']['ip_packets'],0)
    def test_linux_cooked_headers(self):
        payload=syns(1)[0][14:]
        sll=b'\0'*14+struct.pack('!H',0x800)+payload
        sll2=struct.pack('!H',0x800)+b'\0'*18+payload
        for frame,link in ((sll,113),(sll2,276)):
            self.assertEqual(analyze(pcap([frame],linktype=link))['packet_preview'][0]['destination_port'],20)
    def test_vlan_ethertype_decoding(self):
        frame=syns(1)[0];tagged=frame[:12]+struct.pack('!HHH',0x8100,1,0x800)+frame[14:]
        self.assertEqual(analyze(pcap([tagged]))['summary']['ip_packets'],1)
    def test_ipv4_fragment_not_transport_decoded(self):
        payload=syns(1)[0][34:];frame=ethernet(ip4('192.0.2.1','203.0.113.1',6,payload,fragment=0x2000))
        r=analyze(pcap([frame]));self.assertEqual(r['summary']['ip_packets'],1);self.assertIsNone(r['packet_preview'][0]['tcp_flags']);self.assertEqual(r['parse_status'],'partial')
    def test_ipv6_direct_udp(self):
        import ipaddress
        seg=struct.pack('!HHHH',50000,50001,8,0)
        header=struct.pack('!IHBB',6<<28,len(seg),17,64)+ipaddress.ip_address('2001:db8::1').packed+ipaddress.ip_address('2001:db8::2').packed
        r=analyze(pcap([ethernet(header+seg,0x86dd)]));self.assertEqual(r['packet_preview'][0]['source_ip'],'2001:db8::1');self.assertEqual(r['packet_preview'][0]['destination_port'],50001)
    def test_ipv6_extension_reported(self):
        import ipaddress
        h=struct.pack('!IHBB',6<<28,8,44,64)+ipaddress.ip_address('2001:db8::1').packed+ipaddress.ip_address('2001:db8::2').packed
        r=analyze(pcap([ethernet(h+b'\0'*8,0x86dd)]));self.assertEqual(r['parse_status'],'partial')
    def test_dns_query_and_nxdomain(self):
        self.assertEqual(dns(dns_message('hello.example.test'))['questions'][0]['name'],'hello.example.test')
        self.assertEqual(dns(dns_message(response=True,rcode=3))['rcode'],3)
    def test_dns_compression_back_pointer(self):
        data=b'\0'*12+b'\x03www\x07example\x04test\0';pos=len(data)
        data+=b'\xc0\x0c'
        labels,end=dns_name(data,pos);self.assertEqual(labels,[b'www',b'example',b'test']);self.assertEqual(end,pos+2)
    def test_dns_cyclic_forward_and_truncated_pointers(self):
        for data,pos in ((b'\xc0\x00',0),(b'\xc0',0),(b'\x40',0),(b'\x03ab',0)):
            with self.assertRaises(ValueError):dns_name(data,pos)
    def test_dns_question_cap(self):
        with self.assertRaises(ValueError):dns(struct.pack('!6H',1,0,17,0,0,0))
    def test_malformed_dns_diagnostic_not_query(self):
        r=analyze(pcap([udp('192.0.2.1','198.51.100.53',50000,53,b'bad')]))
        self.assertEqual(r['summary']['dns_packets'],0);self.assertEqual(r['parse_status'],'partial')
    def test_plaintext_payload_never_exported(self):
        r=analyze(fixture('plaintext.pcap'));self.assertEqual(r['summary']['informational_observations'],1)
        for secret in ('DO_NOT_EXPORT','DEMO_ONLY_NOT_SECRET','Authorization','/account?'):
            self.assertNotIn(secret,json.dumps(r));self.assertNotIn(secret,to_csv(r))
    def test_capture_truncation_diagnostics(self):
        r=analyze(fixture('partial.pcap'));self.assertEqual(r['summary']['packet_records'],7)
        self.assertEqual(r['summary']['capture_truncated_packets'],1);self.assertEqual(r['summary']['packets_with_issues'],1)

class RuleTests(unittest.TestCase):
    def test_review_sample_has_three_rules(self):
        r=analyze(fixture('suspicious.pcap'));self.assertEqual(r['summary']['packet_records'],19)
        self.assertEqual(r['summary']['directional_flows'],14);self.assertEqual(r['alert_counts'],{'PCI-001':1,'PCI-002':1,'PCI-003':1})
    def test_distinct_port_threshold_and_retransmission(self):
        self.assertNotIn('PCI-001',analyze(pcap(syns(9)))['alert_counts'])
        self.assertIn('PCI-001',analyze(pcap(syns(10)))['alert_counts'])
        self.assertNotIn('PCI-001',analyze(pcap(syns(1)*20))['alert_counts'])
    def test_synack_not_counted_as_initial_syn(self):self.assertNotIn('PCI-001',analyze(pcap(syns(12,0x12)))['alert_counts'])
    def test_window_outside_and_inclusive(self):
        frames=syns(3)
        inclusive=[(f,t,len(f)) for f,t in zip(frames,[0,30,60])]
        outside=[(f,t,len(f)) for f,t in zip(frames,[0,30,61])]
        self.assertIn('PCI-001',analyze(pcap(inclusive),port_threshold=3)['alert_counts'])
        self.assertNotIn('PCI-001',analyze(pcap(outside),port_threshold=3)['alert_counts'])
    def test_destination_scope(self):
        frames=syns(6)+[tcp('192.0.2.1','203.0.113.2',50000,30+i) for i in range(6)]
        self.assertNotIn('PCI-001',analyze(pcap(frames))['alert_counts'])
    def test_out_of_order_time_not_rewritten(self):
        frames=syns(3);data=pcap([(f,t,len(f)) for f,t in zip(frames,[2,0,1])])
        r=analyze(data,port_threshold=3);self.assertIn('PCI-001',r['alert_counts']);self.assertTrue(any('out of order' in w for w in r['warnings']))
    def test_no_network(self):
        with patch('socket.socket',side_effect=AssertionError('network')),patch('socket.getaddrinfo',side_effect=AssertionError('DNS')):
            self.assertEqual(analyze(fixture('normal.pcapng'))['summary']['packet_records'],6)
    def test_invalid_threshold(self):
        for value in (True,2,101,'10'):
            with self.assertRaises(CaptureError):analyze(fixture('normal.pcap'),port_threshold=value)
    def test_csv_columns_and_formula_guard(self):
        r=analyze(fixture('normal.pcap'));rows=list(csv.reader(io.StringIO(to_csv(r))))
        self.assertEqual(len(rows),5);self.assertTrue(all(len(x)==len(rows[0]) for x in rows))
        for v in ('=1','+x','-x','@SUM(1)','  =1'):self.assertTrue(csv_safe(v).startswith("'"))

class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start();cls.url=f'http://127.0.0.1:{cls.server.server_port}'
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def post(self,headers=None,payload=None):
        payload=payload if payload is not None else {'filename':'normal.pcapng','data':base64.b64encode(fixture('normal.pcapng')).decode()}
        return urlopen(Request(self.url+'/analyze',data=json.dumps(payload).encode(),headers=headers or {'X-PCAP-Inspector':'local','Content-Type':'application/json'}))
    def test_upload_to_report(self):
        with self.post() as r:d=json.load(r)
        self.assertEqual(d['report']['summary']['packet_records'],6);self.assertIn('csv',d)
    def test_origin_and_header_restrictions(self):
        for h in ({'X-PCAP-Inspector':'local','Origin':'https://other.test'},{'Content-Type':'application/json'}):
            with self.assertRaises(HTTPError) as e:self.post(h)
            self.assertEqual(e.exception.code,403)
    def test_bad_capture_rejected(self):
        with self.assertRaises(HTTPError) as e:self.post(payload={'filename':'x','data':'%%%'} )
        self.assertEqual(e.exception.code,400)
    def test_ui_samples_static_routes(self):
        with urlopen(self.url) as r:self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy'])
        with urlopen(self.url+'/sample/normal') as r:self.assertEqual(json.load(r)['filename'],'normal.pcap')
        with self.assertRaises(HTTPError) as e:urlopen(self.url+'/capture.py')
        self.assertEqual(e.exception.code,404)

if __name__=='__main__':unittest.main()
