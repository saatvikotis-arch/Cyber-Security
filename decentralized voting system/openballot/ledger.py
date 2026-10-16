from typing import Dict, Set, List, Optional
from openballot.block import Block

GENESIS_PREV_HASH = "0" * 64


class Ledger:
    def __init__(self, voter_registry: Optional[Set[str]] = None):
        self.chain: List[Block] = []
        self.voter_registry: Set[str] = voter_registry or set()

    def create_genesis_block(self) -> Block:
        if self.chain:
            return self.chain[0]
        genesis = Block(
            index=0,
            prev_hash=GENESIS_PREV_HASH,
            ballots=[],
            timestamp=1700000000.0,
            nonce=0
        )
        self.chain.append(genesis)
        return genesis

    def register_voter(self, voter_id: str):
        self.voter_registry.add(voter_id.strip().lower())

    def is_registered(self, voter_id: str) -> bool:
        if not self.voter_registry:
            # If no registry provided, open voter policy
            return True
        return voter_id.strip().lower() in self.voter_registry

    def has_voted(self, proposal_id: str, voter_id: str) -> bool:
        vid = voter_id.strip().lower()
        pid = proposal_id.strip()
        for block in self.chain:
            for ballot in block.ballots:
                if ballot.proposal_id.strip() == pid and ballot.voter_id.strip().lower() == vid:
                    return True
        return False

    def tally(self, proposal_id: str) -> Dict[str, int]:
        results: Dict[str, int] = {}
        seen_voters = set()
        pid = proposal_id.strip()
        for block in self.chain:
            for ballot in block.ballots:
                if ballot.proposal_id.strip() == pid:
                    vid = ballot.voter_id.strip().lower()
                    if vid not in seen_voters:
                        seen_voters.add(vid)
                        results[ballot.choice] = results.get(ballot.choice, 0) + ballot.weight
        return results

    def get_proposals(self) -> List[str]:
        proposals = set()
        for block in self.chain:
            for ballot in block.ballots:
                if ballot.proposal_id:
                    proposals.add(ballot.proposal_id.strip())
        return sorted(proposals)

    @property
    def latest_block(self) -> Block:
        if not self.chain:
            self.create_genesis_block()
        return self.chain[-1]
