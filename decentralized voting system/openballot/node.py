import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional, List, Dict, Any

from openballot.ballot import Ballot
from openballot.block import Block
from openballot.ledger import Ledger
from openballot.mempool import Mempool
from openballot.consensus import ConsensusEngine

logger = logging.getLogger("openballot.node")


class NodeServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, ledger: Ledger, difficulty: int = 1):
        super().__init__(server_address, RequestHandlerClass)
        self.ledger = ledger
        self.mempool = Mempool()
        self.consensus = ConsensusEngine(ledger=self.ledger, difficulty=difficulty)
        self.difficulty = difficulty
        self.peers: List[str] = []
        if not self.ledger.chain:
            self.ledger.create_genesis_block()


class NodeHandler(BaseHTTPRequestHandler):
    @property
    def node(self) -> NodeServer:
        return self.server

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Optional[Dict[str, Any]]:
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len == 0:
                return {}
            raw = self.rfile.read(content_len).decode("utf-8")
            return json.loads(raw)
        except Exception:
            return None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            return self._send_json({
                "status": "healthy",
                "blocks": len(self.node.ledger.chain),
                "mempool": self.node.mempool.size(),
                "peers": len(self.node.peers)
            })

        elif path == "/api/v1/chain":
            chain_data = [b.to_dict() for b in self.node.ledger.chain]
            return self._send_json({"length": len(chain_data), "chain": chain_data})

        elif path == "/api/v1/mempool":
            ballots_data = [b.to_dict() for b in self.node.mempool.all()]
            return self._send_json({"count": len(ballots_data), "ballots": ballots_data})

        elif path == "/api/v1/tally":
            qs = parse_qs(parsed.query)
            proposal = qs.get("proposal", [""])[0]
            if not proposal:
                return self._send_json({"error": "Missing proposal query parameter"}, 400)
            tally = self.node.ledger.tally(proposal)
            return self._send_json({"proposal": proposal, "results": tally})

        elif path == "/api/v1/peers":
            return self._send_json({"peers": self.node.peers})

        else:
            return self._send_json({"error": "Endpoint not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        data = self._read_json()

        if data is None:
            return self._send_json({"error": "Invalid JSON payload"}, 400)
        if not isinstance(data, dict):
            return self._send_json({"error": "JSON payload must be an object"}, 400)

        if path == "/api/v1/ballots":
            try:
                ballot = Ballot.from_dict(data)
            except (AttributeError, TypeError, ValueError):
                return self._send_json({"error": "Invalid ballot format"}, 400)

            if not ballot.voter_id or not ballot.proposal_id or not ballot.choice:
                return self._send_json({"error": "Missing required ballot fields"}, 400)

            # Enforce democratic standard weight = 1
            if ballot.weight != 1:
                return self._send_json({"error": "Invalid vote weight: standard elections require weight=1"}, 400)

            # 1. Verify digital signature
            if not ballot.verify():
                return self._send_json({"error": "Cryptographic signature verification failed"}, 401)

            # 2. Verify voter registration (case-insensitive whitelist)
            if not self.node.ledger.is_registered(ballot.voter_id):
                return self._send_json({"error": "Voter ID not in authorized voter registry"}, 403)

            # 3. Check if voter already cast ballot on confirmed ledger
            if self.node.ledger.has_voted(ballot.proposal_id, ballot.voter_id):
                return self._send_json({"error": "Voter has already cast a ballot for this proposal"}, 409)

            # 4. Check if voter already has a ballot pending in mempool
            if self.node.mempool.has_ballot(ballot.proposal_id, ballot.voter_id):
                return self._send_json({"error": "A ballot for this voter is already pending in the mempool"}, 409)

            # Ingest ballot into mempool
            if not self.node.mempool.add(ballot):
                return self._send_json({"error": "Duplicate ballot in mempool"}, 409)

            return self._send_json({"status": "accepted", "proposal": ballot.proposal_id}, 202)

        elif path == "/api/v1/mine":
            pending = self.node.mempool.drain()
            valid_ballots = []
            seen_in_block = set()
            for b in pending:
                vote_key = (b.proposal_id.strip(), b.voter_id.strip().lower())
                if (
                    b.verify()
                    and b.weight == 1
                    and self.node.ledger.is_registered(b.voter_id)
                    and not self.node.ledger.has_voted(b.proposal_id, b.voter_id)
                    and vote_key not in seen_in_block
                ):
                    valid_ballots.append(b)
                    seen_in_block.add(vote_key)

            new_block = Block(
                index=len(self.node.ledger.chain),
                prev_hash=self.node.ledger.chain[-1].hash,
                ballots=valid_ballots
            )
            new_block.mine(difficulty=self.node.difficulty)
            self.node.ledger.chain.append(new_block)
            return self._send_json({
                "status": "mined",
                "block_index": new_block.index,
                "block_hash": new_block.hash,
                "ballots_sealed": len(valid_ballots)
            })

        elif path == "/api/v1/peers":
            peer = data.get("peer")
            if peer and peer not in self.node.peers:
                self.node.peers.append(peer)
            return self._send_json({"peers": self.node.peers})

        elif path == "/api/v1/sync":
            # Peer pushes a candidate chain for consensus resolution
            candidate_raw = data.get("chain", [])
            if not candidate_raw:
                return self._send_json({"error": "Empty chain provided"}, 400)
            try:
                candidate = [Block.from_dict(b) for b in candidate_raw]
            except Exception as e:
                return self._send_json({"error": f"Invalid block format: {e}"}, 400)

            replaced = self.node.consensus.resolve_conflicts([candidate])
            return self._send_json({
                "chain_replaced": replaced,
                "current_length": len(self.node.ledger.chain)
            })

        else:
            return self._send_json({"error": "Endpoint not found"}, 404)

    def log_message(self, format, *args):
        # Silence default stderr logging for clean test runs
        return
