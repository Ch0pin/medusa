import threading
import socketserver
import socket
import logging
from libraries.logging_config import setup_logging

logging.getLogger().handlers = []  
setup_logging() 
logger = logging.getLogger(__name__)

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(1.0) 
        self.server.register_client(self.request)
        try:
            while True:
                try:
                    self.data = self.request.recv(1024).strip()
                    if not self.data or "close" in self.data.decode('utf-8'):
                        break
                    logger.debug(f"Received data from {self.client_address[0]}:{self.client_address[1]}")
                    logger.debug(f"Data: {self.data}")
                except socket.timeout:
                    continue
        finally:
            self.server.unregister_client(self.request)
            self.request.close()

class TCPServer(socketserver.ThreadingTCPServer):
    def __init__(self, host="localhost", port=1711):
        self.server_address = (host, port)
        super().__init__(self.server_address, MyTCPHandler)
        self.clients = []
        self.server_thread = None

    def register_client(self, client):
        self.clients.append(client)

    def unregister_client(self, client):
        self.clients.remove(client)

    def broadcast(self, message):
        for client in self.clients:
            try:
                client.sendall(message.encode('utf-8'))
            except BrokenPipeError:
                self.unregister_client(client)

    def start(self):
        if not self.server_thread or not self.server_thread.is_alive():
            self.server_thread = threading.Thread(target=self.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            logger.info(f"Listening at {self.server_address[0]}:{self.server_address[1]}")

    def stop(self):
        if self.server_thread and self.server_thread.is_alive():
            self.shutdown()
            self.server_close()
            self.server_thread.join()
            logger.info("Server stopped")


