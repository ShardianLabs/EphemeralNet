import http.server
import subprocess

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/metrics':
            self.send_response(404)
            self.end_headers()
            return
        result = subprocess.run(
            ['./build/eph', 'metrics', '--format', 'prometheus'],
            capture_output=True,
            text=True,
            check=True,
        )
        body = result.stdout.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; version=0.0.4')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    server = http.server.ThreadingHTTPServer(('', 9001), Handler)
    print('Serving metrics on http://localhost:9001/metrics')
    server.serve_forever()
