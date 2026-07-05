"""Workload CA + X.509 SVID issuance (Phase 5 Track A, D5.1). [RUNNABLE]

Closes the identity-issuance half of the vision's Layer A ("Identity,
Trust, and Admission"). The substrate has used SPIFFE-*format* strings
as identity since Phase 0, but nothing actually bound those strings to
a cryptographic identity document. This module does: an internal
:class:`WorkloadCA` mints short-lived X.509 certificates whose Subject
Alternative Name carries the SPIFFE ID as a URI — i.e. a SPIFFE SVID
(SPIFFE Verifiable Identity Document), the same shape SPIRE issues.

Design:

- The CA root is an Ed25519 keypair (the substrate's pinned signature
  algorithm). Its self-signed root cert is the trust anchor a verifier
  loads out-of-band, exactly like the :mod:`bootstrap_bundle` anchor.
- :meth:`WorkloadCA.issue_svid` signs a leaf cert binding a workload's
  Ed25519 public key to its ``spiffe://`` id via a critical URI SAN,
  with a short validity window (default 1 hour — the vision's
  "hours, not weeks" rotation cadence).
- Serial numbers are caller-supplied for determinism in tests, or
  random in production. ``not_before``/``not_after`` come from an
  explicit clock so issuance is reproducible.

Verification lives in the companion :func:`verify_svid` (Track A A2).
This slice is issuance-only; it deliberately does not verify, so the
two halves stay independently reviewable.

Scope / enforcement boundary
----------------------------
This is a *reference* CA suitable for a single trust domain in a
controlled deployment. It is RUNNABLE and fully tested, but it is NOT
a production PKI: no HSM/KMS key custody, no OCSP/CRL responders, no
path-length or name-constraints beyond the SPIFFE-SAN binding, no
intermediate-CA hierarchy. Those are deployment concerns
(see DEFERRED.md, Phase 6 pool). What it *does* give you is a real,
verifiable cryptographic binding from a SPIFFE id to a keypair, which
is what Layer A needs before mTLS or admission can mean anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import NameOID
from verify_envelope import SPIFFE_ID_RE


class WorkloadCAError(ValueError):
    """Raised when CA issuance inputs violate v0 invariants."""


# A short default so an operator who forgets to set a lifetime still
# gets the vision's "hours, not weeks" behavior rather than a stale
# long-lived cert.
_DEFAULT_SVID_TTL = timedelta(hours=1)


def _spiffe_trust_domain(spiffe_id: str) -> str:
    # spiffe://<trust-domain>/<path...> — the authority component.
    without_scheme = spiffe_id[len("spiffe://") :]
    return without_scheme.split("/", 1)[0]


@dataclass
class WorkloadCA:
    """An internal certificate authority for one trust domain.

    ``root_key`` signs every SVID. ``trust_domain`` is the authority
    component all issued SPIFFE ids must share, so one CA cannot mint
    an identity outside its own domain.
    """

    trust_domain: str
    root_key: Ed25519PrivateKey
    common_name: str = "wt-workload-ca"
    _root_cert: x509.Certificate = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.trust_domain, str) or not self.trust_domain:
            raise WorkloadCAError("trust_domain must be a non-empty string")
        # A trust domain must be a valid SPIFFE authority (no scheme,
        # no path). Validate by constructing a canonical id from it.
        probe = f"spiffe://{self.trust_domain}/probe"
        if not SPIFFE_ID_RE.match(probe):
            raise WorkloadCAError(
                f"trust_domain is not a valid SPIFFE authority: "
                f"{self.trust_domain!r}"
            )
        if not isinstance(self.root_key, Ed25519PrivateKey):
            raise WorkloadCAError("root_key must be an Ed25519PrivateKey")

    @property
    def root_cert(self) -> x509.Certificate:
        """The CA's self-signed root cert — the trust anchor verifiers load.

        Built lazily and cached. Valid for 10 years (a root, not an
        SVID; roots rotate on the key-rotation overlap schedule, not
        the SVID cadence)."""
        if self._root_cert is None:
            name = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, self.common_name)]
            )
            # Anchor validity is deliberately wide; the substrate's
            # key_rotation primitive governs actual root cutover.
            not_before = datetime(2020, 1, 1, tzinfo=UTC)
            not_after = datetime(2030, 1, 1, tzinfo=UTC)
            builder = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(self.root_key.public_key())
                .serial_number(1)
                .not_valid_before(not_before)
                .not_valid_after(not_after)
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=0), critical=True
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=False,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
            )
            self._root_cert = builder.sign(self.root_key, None)
        return self._root_cert

    def issue_svid(
        self,
        *,
        spiffe_id: str,
        public_key: Ed25519PublicKey,
        now: datetime,
        ttl: timedelta = _DEFAULT_SVID_TTL,
        serial_number: int | None = None,
    ) -> x509.Certificate:
        """Mint a leaf SVID binding ``public_key`` to ``spiffe_id``.

        The SPIFFE id is carried in a critical URI SAN. The workload's
        own key goes in the cert; the CA root signs it. Raises
        :class:`WorkloadCAError` if the id is malformed or outside this
        CA's trust domain.
        """
        if not isinstance(spiffe_id, str) or not SPIFFE_ID_RE.match(spiffe_id):
            raise WorkloadCAError(f"invalid spiffe_id: {spiffe_id!r}")
        if _spiffe_trust_domain(spiffe_id) != self.trust_domain:
            raise WorkloadCAError(
                f"spiffe_id {spiffe_id!r} is outside CA trust domain "
                f"{self.trust_domain!r}"
            )
        if not isinstance(public_key, Ed25519PublicKey):
            raise WorkloadCAError("public_key must be an Ed25519PublicKey")
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise WorkloadCAError("now must be a timezone-aware datetime")
        if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
            raise WorkloadCAError("ttl must be a positive timedelta")

        not_before = now.astimezone(UTC)
        not_after = not_before + ttl
        # The leaf subject CN mirrors the SPIFFE path tail for human
        # readability; identity of record is the SAN, per SPIFFE.
        leaf_cn = spiffe_id.rsplit("/", 1)[-1] or "workload"
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, leaf_cn)])
            )
            .issuer_name(self.root_cert.subject)
            .public_key(public_key)
            .serial_number(
                serial_number
                if serial_number is not None
                else x509.random_serial_number()
            )
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(spiffe_id)]
                ),
                critical=True,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )
        return builder.sign(self.root_key, None)


def svid_spiffe_id(cert: x509.Certificate) -> str:
    """Extract the SPIFFE id from an SVID's URI SAN.

    Raises :class:`WorkloadCAError` if the cert carries zero or more
    than one URI SAN (a well-formed SVID carries exactly one)."""
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound as exc:
        raise WorkloadCAError("certificate has no SubjectAlternativeName") from exc
    uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    spiffe_uris = [u for u in uris if u.startswith("spiffe://")]
    if len(spiffe_uris) != 1:
        raise WorkloadCAError(
            f"SVID must carry exactly one spiffe:// URI SAN, found "
            f"{len(spiffe_uris)}"
        )
    return spiffe_uris[0]
