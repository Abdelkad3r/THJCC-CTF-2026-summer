from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
v=Path('/flag.txt').read_bytes()
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.headers.get('Host','').split(':')[0].lower()!='flag.thjcc':self.send_response(403);self.end_headers();return
  if self.path!='/flag.txt':self.send_response(404);self.end_headers();return
  self.send_response(200);self.end_headers();self.wfile.write(v)
 def log_message(self,*x):pass
HTTPServer(('0.0.0.0',80),H).serve_forever()
