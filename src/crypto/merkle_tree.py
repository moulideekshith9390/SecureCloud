"""Merkle Hash Tree implementation for tamper-evident data integrity verification."""

import hashlib
from typing import List, Optional, Tuple


def sha256(data: bytes) -> bytes:
      return hashlib.sha256(data).digest()


class MerkleNode:
      """A node in the Merkle tree."""

    def __init__(self, left=None, right=None, data: bytes = b""):
              self.left: Optional[MerkleNode] = left
              self.right: Optional[MerkleNode] = right
              if left is None and right is None:
                            self.hash = sha256(data)
else:
            combined = (left.hash if left else b"") + (right.hash if right else b"")
              self.hash = sha256(combined)


class MerkleTree:
      """Merkle Hash Tree for verifying integrity of stored data blocks.

          Leaves correspond to individual data blocks. The root hash represents
              the entire dataset. Any modification to any block changes the root hash,
                  enabling efficient tamper detection.
                      """

    def __init__(self, data_blocks: List[bytes]):
              if not data_blocks:
                            raise ValueError("Cannot build a Merkle tree from empty data")
                        self._leaves = [MerkleNode(data=block) for block in data_blocks]
        self._root = self._build(self._leaves)

    @property
    def root_hash(self) -> bytes:
              return self._root.hash

    @property
    def root_hex(self) -> str:
              return self._root.hash.hex()

    def _build(self, nodes: List[MerkleNode]) -> MerkleNode:
              if len(nodes) == 1:
                            return nodes[0]
                        if len(nodes) % 2 != 0:
                                      nodes.append(nodes[-1])
                                  parent_layer = []
        for i in range(0, len(nodes), 2):
                      parent_layer.append(MerkleNode(left=nodes[i], right=nodes[i + 1]))
                  return self._build(parent_layer)

    def get_proof(self, index: int) -> List[Tuple[str, bytes]]:
              """Return the Merkle proof (audit path) for the leaf at index.

                      Each element is ('left' | 'right', sibling_hash).
                              """
        proof = []
        leaves = list(self._leaves)
        if len(leaves) % 2 != 0:
                      leaves.append(leaves[-1])
                  self._collect_proof(leaves, index, proof)
        return proof

    def _collect_proof(self, nodes, index, proof):
              if len(nodes) == 1:
                            return
                        if len(nodes) % 2 != 0:
                                      nodes.append(nodes[-1])
                                  if index % 2 == 0:
                                                sibling_index = index + 1
                                                proof.append(("right", nodes[sibling_index].hash))
else:
            sibling_index = index - 1
            proof.append(("left", nodes[sibling_index].hash))
        parent_nodes = []
        for i in range(0, len(nodes), 2):
                      parent_nodes.append(MerkleNode(left=nodes[i], right=nodes[i + 1]))
                  self._collect_proof(parent_nodes, index // 2, proof)

    @staticmethod
    def verify_proof(leaf_data: bytes, proof: List[Tuple[str, bytes]], root_hash: bytes) -> bool:
              """Verify a Merkle proof for a leaf against a known root hash."""
        current = sha256(leaf_data)
        for direction, sibling in proof:
                      if direction == "right":
                                        current = sha256(current + sibling)
else:
                current = sha256(sibling + current)
          return current == root_hash
