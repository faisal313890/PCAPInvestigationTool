"""Loopback upload/report UI. No live capture or outbound traffic."""
import base64,binascii,json,os
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from analyzer import analyze,to_csv
from capture import CaptureError,MAX_BYTES
ROOT=Path(__file__).resolve().parent
SAMPLES={'normal':'normal.pcap','pcapng':'normal.pcapng','suspicious':'suspicious.pcap','plaintext':'plaintext.pcap','partial':'partial.pcap'}
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def reply(self,code,data,mime='application/json'):
        body=json.dumps(data,ensure_ascii=True).encode() if mime=='application/json' else data
        self.send_response(code)
        for k,v in {'Content-Type':mime,'Content-Length':str(len(body)),'Cache-Control':'no-store',
         'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
         'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"}.items():self.send_header(k,v)
        self.end_headers();self.wfile.write(body)
    def local(self):return self.headers.get('Host') in {f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}'}
    def do_GET(self):
        if not self.local():return self.reply(403,{'error':'Local host required.'})
        if self.path.startswith('/sample/'):
            key=self.path[len('/sample/'):]
            if key not in SAMPLES:return self.reply(404,{'error':'Unknown sample.'})
            name=SAMPLES[key];return self.reply(200,{'filename':name,'data':base64.b64encode((ROOT/'examples'/name).read_bytes()).decode()})
        routes={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript'),'/style.css':('style.css','text/css')}
        if self.path not in routes:return self.reply(404,{'error':'Not found.'})
        name,mime=routes[self.path];self.reply(200,(ROOT/'static'/name).read_bytes(),mime)
    def do_POST(self):
        allowed={f'http://127.0.0.1:{self.server.server_port}',f'http://localhost:{self.server.server_port}'}
        if not self.local() or self.headers.get('X-PCAP-Inspector')!='local' or (self.headers.get('Origin') and self.headers['Origin'] not in allowed):return self.reply(403,{'error':'Local requests only.'})
        if self.path!='/analyze':return self.reply(404,{'error':'Not found.'})
        try:
            self.connection.settimeout(15)
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=14*1024*1024+4096:return self.reply(413,{'error':'Upload exceeds the 10 MiB capture limit.'})
            d=json.loads(self.rfile.read(length))
            if not isinstance(d,dict) or not isinstance(d.get('data'),str) or not isinstance(d.get('filename'),str):raise CaptureError('Invalid capture upload.')
            data=base64.b64decode(d['data'],validate=True)
            if len(data)>MAX_BYTES:raise CaptureError('Capture exceeds 10 MiB.')
            report=analyze(data,d['filename'],d.get('port_threshold',10));self.reply(200,{'report':report,'csv':to_csv(report)})
        except (ValueError,UnicodeError,binascii.Error) as exc:self.reply(400,{'error':str(exc)[:240]})
        except TimeoutError:self.reply(408,{'error':'Input timed out.'})
        except (BrokenPipeError,ConnectionResetError):pass
        except Exception:self.reply(500,{'error':'Capture analysis could not be completed.'})
if __name__=='__main__':
    port=int(os.environ.get('PCAP_TOOL_PORT','8810'));server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    print(f'PCAP Investigation Tool: http://127.0.0.1:{port} — Ctrl+C to stop.')
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
