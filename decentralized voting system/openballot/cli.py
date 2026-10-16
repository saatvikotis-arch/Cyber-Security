import argparse
import json
import sys
import urllib.request
import urllib.error
from typing import Optional

from openballot.crypto import (
    generate_keypair,
    public_key_to_hex,
    private_key_to_hex,
    private_key_from_hex,
    sign_message
)
from openballot.ballot import Ballot
from openballot.block import Block
from openballot.ledger import Ledger
from openballot.node import NodeServer, NodeHandler


def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        try:
            return json.loads(err_msg)
        except Exception:
            return {"error": f"HTTP {e.code}: {err_msg}"}


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        try:
            return json.loads(err_msg)
        except Exception:
            return {"error": f"HTTP {e.code}: {err_msg}"}


def cmd_keygen(args):
    priv, pub = generate_keypair()
    priv_hex = private_key_to_hex(priv)
    pub_hex = public_key_to_hex(pub)
    print("Generated Ed25519 Keypair:")
    print(f"  Voter ID (Public Key): {pub_hex}")
    print(f"  Secret Key           : {priv_hex}")
    if args.save:
        with open(args.save, "w") as f:
            json.dump({"voter_id": pub_hex, "secret_key": priv_hex}, f, indent=2)
        print(f"Saved keypair to {args.save}")


def cmd_vote(args):
    try:
        priv = private_key_from_hex(args.key)
        pub = priv.public_key()
        voter_id = public_key_to_hex(pub)
    except Exception as e:
        print(f"Error loading private key: {e}", file=sys.stderr)
        sys.exit(1)

    ballot = Ballot(
        voter_id=voter_id,
        proposal_id=args.proposal,
        choice=args.choice.upper(),
        weight=args.weight
    )
    sig = sign_message(priv, ballot.get_digest())
    ballot.signature = sig.hex()

    endpoint = f"{args.node.rstrip('/')}/api/v1/ballots"
    res = _post_json(endpoint, ballot.to_dict())
    print("Server response:", json.dumps(res, indent=2))


def cmd_mine(args):
    endpoint = f"{args.node.rstrip('/')}/api/v1/mine"
    res = _post_json(endpoint, {})
    print("Miner response:", json.dumps(res, indent=2))


def cmd_tally(args):
    endpoint = f"{args.node.rstrip('/')}/api/v1/tally?proposal={args.proposal}"
    res = _get_json(endpoint)
    print("Election Results:")
    print(json.dumps(res, indent=2))


def cmd_status(args):
    endpoint = f"{args.node.rstrip('/')}/health"
    res = _get_json(endpoint)
    print("Node Status:")
    print(json.dumps(res, indent=2))


def cmd_verify(args):
    """
    Cryptographically audits the entire blockchain downloaded from a node:
    verifies genesis block, block hash continuity, proof-of-work difficulty,
    Ed25519 ballot digital signatures, and double-voting detection.
    """
    endpoint = f"{args.node.rstrip('/')}/api/v1/chain"
    res = _get_json(endpoint)
    if "error" in res:
        print(f"Error connecting to node: {res['error']}", file=sys.stderr)
        sys.exit(1)

    chain_data = res.get("chain", [])
    if not chain_data:
        print("[!] Blockchain is empty.", file=sys.stderr)
        sys.exit(1)

    try:
        blocks = [Block.from_dict(b) for b in chain_data]
    except Exception as e:
        print(f"[✗] Corrupted block data format: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Auditing blockchain ({len(blocks)} blocks) from {args.node}...\n")
    all_valid = True
    seen_votes = set()

    for idx, block in enumerate(blocks):
        block_ok = True
        reasons = []

        # 1. Genesis check
        if idx == 0:
            if block.index != 0 or block.prev_hash != "0" * 64:
                block_ok = False
                reasons.append("Invalid genesis block structure")
        else:
            prev_block = blocks[idx - 1]
            if block.index != prev_block.index + 1:
                block_ok = False
                reasons.append(f"Index mismatch: expected {prev_block.index + 1}, got {block.index}")
            if block.prev_hash != prev_block.hash:
                block_ok = False
                reasons.append("Hash pointer mismatch with previous block")

        # 2. Block hash & PoW difficulty
        if block.compute_hash() != block.hash:
            block_ok = False
            reasons.append("Block hash mismatch with content payload")
        if idx > 0:
            target = "0" * args.difficulty
            if not block.hash.startswith(target):
                block_ok = False
                reasons.append(f"Proof-of-work target ('{target}') not satisfied")

        # 3. Ballot signatures and deduplication
        for b in block.ballots:
            if not b.verify():
                block_ok = False
                reasons.append(f"Invalid Ed25519 signature from voter {b.voter_id[:8]}...")
            vote_key = (b.proposal_id.strip(), b.voter_id.strip().lower())
            if vote_key in seen_votes:
                block_ok = False
                reasons.append(f"Double voting detected: {b.voter_id[:8]}... on {b.proposal_id}")
            seen_votes.add(vote_key)

        status_symbol = "[✓]" if block_ok else "[✗]"
        print(f"{status_symbol} Block #{block.index:<3} | Hash: {block.hash[:16]}... | Ballots: {len(block.ballots)}")
        if not block_ok:
            all_valid = False
            for r in reasons:
                print(f"    └── Error: {r}")

    print("\n" + "=" * 50)
    if all_valid:
        print("RESULT: Blockchain Cryptographic Audit PASSED (Ledger is Authentic)")
        return True
    else:
        print("RESULT: Blockchain Cryptographic Audit FAILED (Ledger Integrity Compromised)")
        return False


def cmd_serve(args):
    ledger = Ledger()
    ledger.create_genesis_block()
    server = NodeServer(("0.0.0.0", args.port), NodeHandler, ledger=ledger, difficulty=args.difficulty)
    print(f"[*] OpenBallot node running on http://127.0.0.1:{args.port} (difficulty={args.difficulty})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down node.")
        server.server_close()


def main():
    parser = argparse.ArgumentParser(prog="openballot", description="OpenBallot CLI tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate a new voter keypair")
    p_keygen.add_argument("--save", type=str, help="Save keypair to JSON file")
    p_keygen.set_defaults(func=cmd_keygen)

    # vote
    p_vote = subparsers.add_parser("vote", help="Cast a digitally signed ballot")
    p_vote.add_argument("--key", required=True, help="Voter secret key (hex)")
    p_vote.add_argument("--proposal", required=True, help="Proposal ID (e.g. PROP-2026-01)")
    p_vote.add_argument("--choice", required=True, help="Vote choice (e.g. YES, NO)")
    p_vote.add_argument("--weight", type=int, default=1, help="Ballot stake weight (default 1)")
    p_vote.add_argument("--node", default="http://127.0.0.1:8000", help="Node URL")
    p_vote.set_defaults(func=cmd_vote)

    # mine
    p_mine = subparsers.add_parser("mine", help="Seal pending ballots into a block")
    p_mine.add_argument("--node", default="http://127.0.0.1:8000", help="Node URL")
    p_mine.set_defaults(func=cmd_mine)

    # tally
    p_tally = subparsers.add_parser("tally", help="Query election results")
    p_tally.add_argument("--proposal", required=True, help="Proposal ID")
    p_tally.add_argument("--node", default="http://127.0.0.1:8000", help="Node URL")
    p_tally.set_defaults(func=cmd_tally)

    # status
    p_status = subparsers.add_parser("status", help="Get node status")
    p_status.add_argument("--node", default="http://127.0.0.1:8000", help="Node URL")
    p_status.set_defaults(func=cmd_status)

    # verify
    p_verify = subparsers.add_parser("verify", help="Cryptographically audit the blockchain ledger")
    p_verify.add_argument("--node", default="http://127.0.0.1:8000", help="Node URL")
    p_verify.add_argument("--difficulty", type=int, default=1, help="Expected PoW difficulty")
    p_verify.set_defaults(func=cmd_verify)

    # serve
    p_serve = subparsers.add_parser("serve", help="Run node HTTP daemon")
    p_serve.add_argument("--port", type=int, default=8000, help="Listen port")
    p_serve.add_argument("--difficulty", type=int, default=1, help="PoW block difficulty")
    p_serve.set_defaults(func=cmd_serve)

    parsed_args = parser.parse_args()
    ret = parsed_args.func(parsed_args)
    if isinstance(ret, bool) and not ret:
        sys.exit(1)


if __name__ == "__main__":
    main()
