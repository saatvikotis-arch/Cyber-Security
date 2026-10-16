import json
import threading
import urllib.request
import urllib.error
import pytest

from openballot.ballot import Ballot
from openballot.block import Block
from openballot.crypto import generate_keypair, public_key_to_hex, sign_message
from openballot.ledger import Ledger
from openballot.mempool import Mempool
from openballot.node import NodeServer, NodeHandler
from openballot.cli import cmd_verify


def _signed_ballot(private_key, voter_id, proposal_id="PROP-SEC-1", choice="YES", weight=1):
    ballot = Ballot(voter_id, proposal_id, choice, weight=weight)
    ballot.signature = sign_message(private_key, ballot.get_digest()).hex()
    return ballot


def test_mempool_duplicate_rejection():
    priv, pub = generate_keypair()
    vid = public_key_to_hex(pub)
    mempool = Mempool()

    b1 = _signed_ballot(priv, vid, "PROP-1", "YES")
    assert mempool.add(b1) is True

    # Same voter on same proposal must be rejected
    b2 = _signed_ballot(priv, vid, "PROP-1", "NO")
    assert mempool.add(b2) is False
    assert mempool.size() == 1

    # Same voter on different proposal is accepted
    b3 = _signed_ballot(priv, vid, "PROP-2", "YES")
    assert mempool.add(b3) is True
    assert mempool.size() == 2


def test_case_insensitive_has_voted():
    priv, pub = generate_keypair()
    vid_lower = public_key_to_hex(pub).lower()
    vid_upper = vid_lower.upper()

    ledger = Ledger()
    ledger.create_genesis_block()
    ballot = _signed_ballot(priv, vid_lower, "PROP-1", "YES")

    b1 = Block(index=1, prev_hash=ledger.chain[0].hash, ballots=[ballot])
    b1.mine(difficulty=1)
    ledger.chain.append(b1)

    assert ledger.has_voted("PROP-1", vid_lower) is True
    assert ledger.has_voted("PROP-1", vid_upper) is True


def test_tally_deduplication():
    priv, pub = generate_keypair()
    vid = public_key_to_hex(pub)

    ledger = Ledger()
    ledger.create_genesis_block()

    b_original = _signed_ballot(priv, vid, "PROP-1", "YES", weight=1)
    b_dup = _signed_ballot(priv, vid.upper(), "PROP-1", "YES", weight=1)

    # Simulate block containing duplicate ballots for same voter
    b1 = Block(index=1, prev_hash=ledger.chain[0].hash, ballots=[b_original, b_dup])
    b1.mine(difficulty=1)
    ledger.chain.append(b1)

    # Tally must deduplicate by voter ID and count only 1 vote
    tally = ledger.tally("PROP-1")
    assert tally.get("YES") == 1


def test_node_rejects_pending_duplicate_and_weight_inflation():
    ledger = Ledger()
    server = NodeServer(("127.0.0.1", 0), NodeHandler, ledger=ledger, difficulty=1)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        priv, pub = generate_keypair()
        vid = public_key_to_hex(pub)

        # 1. Reject weight inflation
        bad_weight_ballot = _signed_ballot(priv, vid, "PROP-1", "YES", weight=10)
        req_bad = urllib.request.Request(
            f"{base_url}/api/v1/ballots",
            data=json.dumps(bad_weight_ballot.to_dict()).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(urllib.error.HTTPError) as exc_weight:
            urllib.request.urlopen(req_bad)
        assert exc_weight.value.code == 400

        # 2. Accept first legitimate ballot
        good_ballot = _signed_ballot(priv, vid, "PROP-1", "YES", weight=1)
        req_good = urllib.request.Request(
            f"{base_url}/api/v1/ballots",
            data=json.dumps(good_ballot.to_dict()).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_good) as resp:
            assert resp.status == 202

        # 3. Reject duplicate ballot while still in mempool (409 Conflict)
        req_dup = urllib.request.Request(
            f"{base_url}/api/v1/ballots",
            data=json.dumps(good_ballot.to_dict()).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(urllib.error.HTTPError) as exc_dup:
            urllib.request.urlopen(req_dup)
        assert exc_dup.value.code == 409

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_cli_verify_audit_command(capsys):
    ledger = Ledger()
    server = NodeServer(("127.0.0.1", 0), NodeHandler, ledger=ledger, difficulty=1)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        priv, pub = generate_keypair()
        vid = public_key_to_hex(pub)
        b = _signed_ballot(priv, vid, "PROP-AUDIT", "YES")
        ledger.latest_block  # ensure genesis
        block1 = Block(index=1, prev_hash=ledger.chain[0].hash, ballots=[b])
        block1.mine(difficulty=1)
        ledger.chain.append(block1)

        class Args:
            node = base_url
            difficulty = 1

        res = cmd_verify(Args())
        assert res is True
        captured = capsys.readouterr()
        assert "Blockchain Cryptographic Audit PASSED" in captured.out
        assert "Block #0" in captured.out
        assert "Block #1" in captured.out

        # Tamper with block ballot signature and ensure audit catches it
        b.signature = "deadbeef" * 8
        res_fail = cmd_verify(Args())
        assert res_fail is False
        captured_fail = capsys.readouterr()
        assert "Blockchain Cryptographic Audit FAILED" in captured_fail.out
        assert "Invalid Ed25519 signature" in captured_fail.out
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
