"""SecureCloud Proxy Server — main entry point for the database proxy."""

import asyncio
import argparse
import logging
from typing import Optional

from src.auth.rbac import RBACPolicy
from src.auth.session_manager import SessionManager
from src.crypto.aes_gcm import AESGCMCipher
from src.crypto.merkle_tree import MerkleTree
from src.proxy.query_handler import QueryHandler

logging.basicConfig(
      level=logging.INFO,
      format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("securecloud.proxy")


class SecureCloudProxy:
      """Main proxy that wires together auth, encryption, and storage layers."""

    def __init__(self, host: str, port: int, master_key: bytes):
              self.host = host
              self.port = port
              self._cipher = AESGCMCipher(master_key)
              self._rbac = RBACPolicy()
              self._sessions = SessionManager()
              self._handler = QueryHandler(
                  cipher=self._cipher,
                  rbac=self._rbac,
                  session_manager=self._sessions,
              )

    async def handle_client(
              self,
              reader: asyncio.StreamReader,
              writer: asyncio.StreamWriter,
    ) -> None:
              peer = writer.get_extra_info("peername")
              logger.info("New connection from %s", peer)
              try:
                            while True:
                                              data = await reader.read(65536)
                                              if not data:
                                                                    break
                                                                response = await self._handler.process(data)
                                              writer.write(response)
                                              await writer.drain()
              except asyncio.IncompleteReadError:
                            pass
except Exception as exc:
            logger.error("Error handling client %s: %s", peer, exc)
finally:
            writer.close()
              logger.info("Connection closed for %s", peer)

    async def run(self) -> None:
              server = await asyncio.start_server(
                            self.handle_client, self.host, self.port
              )
              addr = server.sockets[0].getsockname()
              logger.info("SecureCloud proxy listening on %s:%s", *addr)
              async with server:
                            await server.serve_forever()


def parse_args():
      parser = argparse.ArgumentParser(description="SecureCloud Database Proxy")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=5432, help="Bind port")
    parser.add_argument(
              "--key-env",
              default="SECURECLOUD_MASTER_KEY",
              help="Environment variable holding hex-encoded 32-byte master key",
    )
    return parser.parse_args()


def main():
      import os

    args = parse_args()
    key_hex = os.environ.get(args.key_env)
    if not key_hex:
              raise RuntimeError(
                            f"Master key not found. Set the {args.key_env} environment variable."
              )
          master_key = bytes.fromhex(key_hex)
    if len(master_key) != 32:
              raise ValueError("Master key must be 32 bytes (64 hex chars)")

    proxy = SecureCloudProxy(host=args.host, port=args.port, master_key=master_key)
    try:
              asyncio.run(proxy.run())
except KeyboardInterrupt:
        logger.info("Proxy stopped.")


if __name__ == "__main__":
      main()
