"""Property / fuzz tests for delegation chains (Phase 2 Track A A3).

Hypothesis suite over random delegation graphs. Pins the **same**
non-escalation invariants as :mod:`envelope.test_delegation_receipt`;
it does not replace those case-based tests and does not add new
safety claims.

v0 requires identical ``scope`` at every hop. Partial-order narrowing
is a different deferred item — this suite treats any scope divergence
as ``DELEGATION_SCOPE_ESCALATION``.
"""

from __future__ import annotations

import unittest
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import Enum, auto

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, assume, given, seed, settings
from hypothesis import strategies as st

from envelope.capability_issuer import generate_uuidv7
from envelope.delegation_receipt import (
    DEFAULT_DELEGATION_CONFIG,
    DelegationError,
    DelegationReceipt,
    ParentClaims,
    parent_from_receipt,
    sign_receipt,
    verify_receipt,
)
from envelope.deny_reason import DenyReason

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_NOW_EPOCH = int(_NOW.timestamp())

_CI_SETTINGS = settings(
    max_examples=40,
    deadline=2000,
    derandomize=True,
    suppress_health_check=(HealthCheck.too_slow,),
)

_LABEL = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=10)
_KID = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=4, max_size=16)
_SCOPE = st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=3, max_size=16)
_RAND10 = st.binary(min_size=10, max_size=10)


def _spiffe(label: str) -> str:
    return f"spiffe://mesh.example/{label}/svc"


def _uuid(rand: bytes) -> str:
    return generate_uuidv7(now=_NOW, rand_bytes=rand)


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


_WRONG_PEM = _keypair()[1]


@dataclass(frozen=True)
class GeneratedChain:
    """A randomly generated, internally consistent delegation chain."""

    hops: tuple[DelegationReceipt, ...]
    keys: dict[tuple[str, str], tuple[Ed25519PrivateKey, bytes]]
    cap_parent: ParentClaims | None = None
    now: datetime = _NOW

    def lookup(self, iss: str, kid: str) -> bytes:
        # Let KeyError propagate. verify_receipt wraps lookup failures as
        # "unknown delegation issuer key: {exc}" — do not prefix here.
        return self.keys[(iss, kid)][1]

    def private(self, iss: str, kid: str) -> Ed25519PrivateKey:
        return self.keys[(iss, kid)][0]


@st.composite
def valid_chains(
    draw,
    *,
    min_hops: int = 1,
    max_hops: int = 3,
    cap_origin: bool = False,
) -> GeneratedChain:
    """Receipt-origin (hop 0) or capability-origin (first hop_index == 1) chains.

    Capability-origin chains are capped at 2 hops: valid ``hop_index``
    values are ``{0, 1, 2}`` under the default depth of 3, so a chain
    that starts at 1 can only add hop 2.
    """
    if cap_origin:
        max_hops = min(max_hops, 2)
    n = draw(st.integers(min_value=min_hops, max_value=max_hops))

    n_ids = n + 2  # n+1 principals + 1 audience
    labels = draw(st.lists(_LABEL, min_size=n_ids, max_size=n_ids, unique=True))
    principals = [_spiffe(lab) for lab in labels[:-1]]
    aud = _spiffe(labels[-1])
    scope = draw(_SCOPE)
    kids = draw(st.lists(_KID, min_size=n, max_size=n))

    n_uuids = n + 2  # chain_id + n jtis + optional cap jti
    rand_blobs = draw(st.lists(_RAND10, min_size=n_uuids, max_size=n_uuids, unique=True))
    chain_id = _uuid(rand_blobs[0])
    jtis = [_uuid(b) for b in rand_blobs[1 : n + 1]]
    cap_jti = _uuid(rand_blobs[-1])

    windows: list[tuple[int, int, int]] = []
    min_iat = _NOW_EPOCH - 60
    max_exp = _NOW_EPOCH + 240
    for _ in range(n):
        iat = draw(st.integers(min_value=min_iat, max_value=_NOW_EPOCH))
        exp = draw(st.integers(min_value=_NOW_EPOCH + 1, max_value=max_exp))
        windows.append((iat, iat, exp))
        min_iat = iat
        max_exp = exp

    keys: dict[tuple[str, str], tuple[Ed25519PrivateKey, bytes]] = {}
    hops: list[DelegationReceipt] = []
    for i in range(n):
        hop_index = i + (1 if cap_origin else 0)
        if hop_index == 0:
            parent_jti = ""
        elif cap_origin and i == 0:
            parent_jti = cap_jti
        else:
            parent_jti = hops[-1].jti
        kid = kids[i]
        delegator = principals[i]
        keys[(delegator, kid)] = _keypair()
        iat, nbf, exp = windows[i]
        unsigned = DelegationReceipt(
            chain_id=chain_id,
            hop_index=hop_index,
            parent_jti=parent_jti,
            delegator_iss=delegator,
            delegator_kid=kid,
            delegate_iss=principals[i + 1],
            scope=scope,
            aud=aud,
            iat=iat,
            nbf=nbf,
            exp=exp,
            jti=jtis[i],
        )
        hops.append(sign_receipt(unsigned, keys[(delegator, kid)][0]))

    cap_parent = None
    if cap_origin:
        cap_parent = ParentClaims(
            jti=cap_jti,
            sub=principals[0],
            aud=aud,
            scope=scope,
            iat=windows[0][0],
            exp=windows[0][2],
            hop_index=-1,
        )
    return GeneratedChain(hops=tuple(hops), keys=keys, cap_parent=cap_parent)


def _verify_chain(chain: GeneratedChain) -> list[DelegationReceipt]:
    verified: list[DelegationReceipt] = []
    parent = chain.cap_parent
    for hop in chain.hops:
        verified.append(
            verify_receipt(
                hop,
                parent=parent,
                issuer_lookup=chain.lookup,
                current=chain.now,
            )
        )
        parent = parent_from_receipt(verified[-1])
    return verified


class GraphMutation(Enum):
    """Structured breaks of an otherwise-valid graph.

    Each member maps onto an already-claimed non-escalation invariant.
    """

    SCOPE_WIDEN = auto()
    SCOPE_NARROW = auto()
    AUDIENCE_DRIFT = auto()
    TTL_EXTEND = auto()
    IAT_BEFORE_PARENT = auto()
    HOP_SKIP = auto()
    PARENT_JTI_MISMATCH = auto()
    DELEGATOR_MISMATCH = auto()
    DEPTH_EXCEEDED = auto()
    TAMPER_DELEGATE = auto()
    WRONG_ISSUER_KEY = auto()


_EXPECTED_REASON: dict[GraphMutation, DenyReason] = {
    GraphMutation.SCOPE_WIDEN: DenyReason.DELEGATION_SCOPE_ESCALATION,
    GraphMutation.SCOPE_NARROW: DenyReason.DELEGATION_SCOPE_ESCALATION,
    GraphMutation.AUDIENCE_DRIFT: DenyReason.DELEGATION_AUDIENCE_DRIFT,
    GraphMutation.TTL_EXTEND: DenyReason.DELEGATION_TTL_ESCALATION,
    GraphMutation.IAT_BEFORE_PARENT: DenyReason.DELEGATION_TTL_ESCALATION,
    GraphMutation.HOP_SKIP: DenyReason.DELEGATION_PARENT_MISMATCH,
    GraphMutation.PARENT_JTI_MISMATCH: DenyReason.DELEGATION_PARENT_MISMATCH,
    GraphMutation.DELEGATOR_MISMATCH: DenyReason.DELEGATION_PARENT_MISMATCH,
    GraphMutation.DEPTH_EXCEEDED: DenyReason.DELEGATION_DEPTH_EXCEEDED,
    GraphMutation.TAMPER_DELEGATE: DenyReason.DELEGATION_SIGNATURE_INVALID,
    GraphMutation.WRONG_ISSUER_KEY: DenyReason.DELEGATION_SIGNATURE_INVALID,
}


def _wrong_issuer_lookup(iss: str, kid: str) -> bytes:
    return _WRONG_PEM


def _resign(
    chain: GeneratedChain, receipt: DelegationReceipt, signer: DelegationReceipt
) -> DelegationReceipt:
    return sign_receipt(receipt, chain.private(signer.delegator_iss, signer.delegator_kid))


def _apply_mutation(
    chain: GeneratedChain, mutation: GraphMutation
) -> tuple[DelegationReceipt, ParentClaims, Callable[[str, str], bytes], DenyReason]:
    """Mutate one hop of a valid (receipt-origin) chain.

    Returns ``(receipt, parent, lookup, expected_reason)``. Prefix hops
    are left intact so the caller can verify them first.
    """
    target_i = 1 if mutation is GraphMutation.HOP_SKIP else len(chain.hops) - 1
    parent = parent_from_receipt(chain.hops[target_i - 1])
    original = chain.hops[target_i]
    receipt = original
    lookup: Callable[[str, str], bytes] = chain.lookup
    expected = _EXPECTED_REASON[mutation]

    if mutation is GraphMutation.SCOPE_WIDEN:
        receipt = _resign(chain, replace(receipt, scope=f"{receipt.scope}_admin"), original)
    elif mutation is GraphMutation.SCOPE_NARROW:
        receipt = _resign(chain, replace(receipt, scope=f"{receipt.scope}:ro"), original)
    elif mutation is GraphMutation.AUDIENCE_DRIFT:
        receipt = _resign(
            chain, replace(receipt, aud="spiffe://mesh.example/mutated-aud/svc"), original
        )
    elif mutation is GraphMutation.TTL_EXTEND:
        receipt = _resign(chain, replace(receipt, exp=parent.exp + 1), original)
    elif mutation is GraphMutation.IAT_BEFORE_PARENT:
        receipt = _resign(
            chain, replace(receipt, iat=parent.iat - 1, nbf=parent.iat - 1), original
        )
    elif mutation is GraphMutation.HOP_SKIP:
        receipt = _resign(chain, replace(receipt, hop_index=parent.hop_index + 2), original)
    elif mutation is GraphMutation.PARENT_JTI_MISMATCH:
        other = _uuid(b"\x11" * 10)
        if other == parent.jti:
            other = _uuid(b"\x22" * 10)
        receipt = _resign(chain, replace(receipt, parent_jti=other), original)
    elif mutation is GraphMutation.DELEGATOR_MISMATCH:
        receipt = _resign(
            chain,
            replace(receipt, delegator_iss="spiffe://mesh.example/mutated-delegator/svc"),
            original,
        )
    elif mutation is GraphMutation.DEPTH_EXCEEDED:
        receipt = _resign(
            chain,
            replace(receipt, hop_index=DEFAULT_DELEGATION_CONFIG.max_chain_depth),
            original,
        )
    elif mutation is GraphMutation.TAMPER_DELEGATE:
        receipt = replace(receipt, delegate_iss="spiffe://mesh.example/tampered-delegate/svc")
    elif mutation is GraphMutation.WRONG_ISSUER_KEY:
        lookup = _wrong_issuer_lookup
    else:
        raise AssertionError(f"unhandled mutation: {mutation}")

    return receipt, parent, lookup, expected


class ValidChainTests(unittest.TestCase):
    @_CI_SETTINGS
    @seed(96)
    @given(valid_chains(min_hops=1, max_hops=3))
    def test_random_valid_chain_verifies(self, chain: GeneratedChain) -> None:
        verified = _verify_chain(chain)
        self.assertEqual(len(verified), len(chain.hops))
        for i, hop in enumerate(verified):
            self.assertEqual(hop.hop_index, i)
            self.assertEqual(hop.scope, chain.hops[0].scope)
            self.assertEqual(hop.aud, chain.hops[0].aud)
            if i == 0:
                self.assertEqual(hop.parent_jti, "")
            else:
                self.assertEqual(hop.parent_jti, verified[i - 1].jti)
                self.assertEqual(hop.delegator_iss, verified[i - 1].delegate_iss)
                self.assertGreaterEqual(hop.iat, verified[i - 1].iat)
                self.assertLessEqual(hop.exp, verified[i - 1].exp)

    @_CI_SETTINGS
    @seed(96)
    @given(valid_chains(min_hops=1, max_hops=2, cap_origin=True))
    def test_cap_originated_chain_verifies(self, chain: GeneratedChain) -> None:
        self.assertIsNotNone(chain.cap_parent)
        verified = _verify_chain(chain)
        self.assertEqual(verified[0].hop_index, 1)
        self.assertEqual(verified[0].parent_jti, chain.cap_parent.jti)
        self.assertEqual(verified[0].delegator_iss, chain.cap_parent.sub)
        self.assertEqual(verified[0].scope, chain.cap_parent.scope)
        self.assertEqual(verified[0].aud, chain.cap_parent.aud)


class MutationFailClosedTests(unittest.TestCase):
    @_CI_SETTINGS
    @seed(96)
    @given(
        valid_chains(min_hops=2, max_hops=3),
        st.sampled_from(list(GraphMutation)),
    )
    def test_mutation_fails_closed_with_expected_reason(
        self, chain: GeneratedChain, mutation: GraphMutation
    ) -> None:
        target_i = 1 if mutation is GraphMutation.HOP_SKIP else len(chain.hops) - 1
        parent = chain.cap_parent
        for hop in chain.hops[:target_i]:
            verified = verify_receipt(
                hop,
                parent=parent,
                issuer_lookup=chain.lookup,
                current=chain.now,
            )
            parent = parent_from_receipt(verified)

        mutated, parent_claims, lookup, expected = _apply_mutation(chain, mutation)
        with self.assertRaises(DelegationError) as ctx:
            verify_receipt(
                mutated,
                parent=parent_claims,
                issuer_lookup=lookup,
                current=chain.now,
            )
        self.assertEqual(ctx.exception.reason, expected)


class BrokenGraphTests(unittest.TestCase):
    @_CI_SETTINGS
    @seed(96)
    @given(valid_chains(min_hops=3, max_hops=3))
    def test_skipped_intermediate_hop_rejected(self, chain: GeneratedChain) -> None:
        root = verify_receipt(
            chain.hops[0],
            parent=None,
            issuer_lookup=chain.lookup,
            current=chain.now,
        )
        with self.assertRaises(DelegationError) as ctx:
            verify_receipt(
                chain.hops[2],
                parent=parent_from_receipt(root),
                issuer_lookup=chain.lookup,
                current=chain.now,
            )
        self.assertEqual(ctx.exception.reason, DenyReason.DELEGATION_PARENT_MISMATCH)

    @_CI_SETTINGS
    @seed(96)
    @given(valid_chains(min_hops=1, max_hops=3), valid_chains(min_hops=1, max_hops=3))
    def test_cross_chain_parent_rejected(
        self, left: GeneratedChain, right: GeneratedChain
    ) -> None:
        foreign = parent_from_receipt(left.hops[0])
        target = right.hops[-1]
        # Independent graphs must not accidentally form a valid pair
        # (UUIDv7 collision plus matching bindings). Root hops fail
        # closed for a different reason: they must not carry a parent.
        assume(target.hop_index == 0 or target.parent_jti != foreign.jti)
        with self.assertRaises(DelegationError) as ctx:
            verify_receipt(
                target,
                parent=foreign,
                issuer_lookup=right.lookup,
                current=right.now,
            )
        self.assertIn(
            ctx.exception.reason,
            {
                DenyReason.DELEGATION_PARENT_MISMATCH,
                DenyReason.DELEGATION_SCOPE_ESCALATION,
                DenyReason.DELEGATION_AUDIENCE_DRIFT,
                DenyReason.DELEGATION_TTL_ESCALATION,
            },
        )


if __name__ == "__main__":
    unittest.main()
