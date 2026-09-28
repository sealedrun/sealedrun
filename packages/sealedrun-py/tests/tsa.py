"""Offline RFC 3161 authority for tests: a throw-away CA and real, signed TimeStampResp bytes.

Tokens are built with asn1crypto and signed with ECDSA P-256, so the verifier exercises the
same path as with a public authority while CI never touches the network. Every knob that a
tampering test needs (nonce, time, imprint, extra certificates, EKU) is a parameter.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta

from asn1crypto import algos, cms, core, tsp
from asn1crypto import x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

POLICY = "1.3.6.1.4.1.99999.1"
NOT_BEFORE = datetime(2025, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime(2035, 1, 1, tzinfo=UTC)


class TestAuthority:
    """A self-signed root, an intermediate and a time-stamping leaf, plus a token builder."""

    __test__ = False

    def __init__(
        self, name: str = "Test TSA", *, leaf_eku: bool = True, root_issuer: str | None = None
    ) -> None:
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        self.root = certificate(
            f"{name} Root", self.root_key, None, None, ca=True, issuer_name=root_issuer
        )
        self.ca = certificate(f"{name} CA", self.ca_key, self.root, self.root_key, ca=True)
        self.leaf = certificate(
            f"{name} Signer", self.leaf_key, self.ca, self.ca_key, ca=False, eku=leaf_eku
        )

    @property
    def root_pem(self) -> str:
        return _pem(self.root)

    @property
    def chain_pems(self) -> list[str]:
        return [_pem(self.leaf), _pem(self.ca), _pem(self.root)]

    def respond(
        self,
        request: bytes,
        *,
        gen_time: datetime | None = None,
        nonce: int | None = None,
        imprint: bytes | None = None,
        include: str = "leaf",
        prepend: list[x509.Certificate | ax509.Certificate] | None = None,
        status: str = "granted",
    ) -> bytes:
        """Answer a TimeStampReq with DER TimeStampResp bytes.

        `include` is `leaf` (only the signer, like Sigstore), `chain` (like DigiCert) or `none`;
        `prepend` puts extra certificates first in the bag; `nonce`, `imprint` and `gen_time`
        override the values taken from the request.
        """
        req = tsp.TimeStampReq.load(request)
        if status != "granted":
            info_only = tsp.PKIStatusInfo({"status": status}).dump()
            return b"\x30" + bytes([len(info_only)]) + info_only
        info = tsp.TSTInfo(
            {
                "version": "v1",
                "policy": POLICY,
                "message_imprint": tsp.MessageImprint(
                    {
                        "hash_algorithm": {"algorithm": "sha256"},
                        "hashed_message": imprint
                        if imprint is not None
                        else req["message_imprint"]["hashed_message"].native,
                    }
                ),
                "serial_number": int.from_bytes(os.urandom(8), "big"),
                "gen_time": gen_time or datetime(2026, 9, 16, 12, 0, 7, tzinfo=UTC),
                "nonce": nonce if nonce is not None else req["nonce"].native,
            }
        )
        content = info.dump()
        leaf = ax509.Certificate.load(self.leaf.public_bytes(serialization.Encoding.DER))
        signed_attrs = cms.CMSAttributes(
            [
                cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
                cms.CMSAttribute(
                    {"type": "message_digest", "values": [hashlib.sha256(content).digest()]}
                ),
                cms.CMSAttribute(
                    {
                        "type": "signing_certificate_v2",
                        "values": [
                            tsp.SigningCertificateV2(
                                {
                                    "certs": [
                                        tsp.ESSCertIDv2(
                                            {
                                                "hash_algorithm": {"algorithm": "sha256"},
                                                "cert_hash": hashlib.sha256(leaf.dump()).digest(),
                                            }
                                        )
                                    ]
                                }
                            )
                        ],
                    }
                ),
            ]
        )
        signature = self.leaf_key.sign(signed_attrs.dump(), ec.ECDSA(hashes.SHA256()))
        certificates = {
            "leaf": [self.leaf],
            "chain": [self.leaf, self.ca, self.root],
            "none": [],
        }[include]
        bag = [
            cms.CertificateChoices({"certificate": _asn1(c)})
            for c in [*(prepend or []), *certificates]
        ]
        signed = cms.SignedData(
            {
                "version": "v3",
                "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
                "encap_content_info": {
                    "content_type": "tst_info",
                    "content": core.ParsableOctetString(content),
                },
                "certificates": bag or None,
                "signer_infos": [
                    cms.SignerInfo(
                        {
                            "version": "v1",
                            "sid": cms.SignerIdentifier(
                                {
                                    "issuer_and_serial_number": {
                                        "issuer": leaf.issuer,
                                        "serial_number": leaf.serial_number,
                                    }
                                }
                            ),
                            "digest_algorithm": {"algorithm": "sha256"},
                            "signed_attrs": signed_attrs,
                            "signature_algorithm": {"algorithm": "sha256_ecdsa"},
                            "signature": signature,
                        }
                    )
                ],
            }
        )
        token = cms.ContentInfo({"content_type": "signed_data", "content": signed})
        return tsp.TimeStampResp(
            {"status": {"status": "granted"}, "time_stamp_token": token}
        ).dump()


def _asn1(certificate: x509.Certificate | ax509.Certificate) -> ax509.Certificate:
    if isinstance(certificate, ax509.Certificate):
        return certificate
    return ax509.Certificate.load(certificate.public_bytes(serialization.Encoding.DER))


def certificate(
    common_name: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: x509.Certificate | None,
    issuer_key: ec.EllipticCurvePrivateKey | None,
    *,
    ca: bool,
    eku: bool = True,
    issuer_name: str | None = None,
    serial: int | None = None,
) -> x509.Certificate:
    """Build a certificate.

    `issuer_name` names an issuer that is not a certificate at hand (a root spelt differently,
    or one half of an issuer cycle signed with `issuer_key`); `serial` fixes the serial number.
    """
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    if issuer is not None:
        issuer_dn = issuer.subject
    elif issuer_name is not None:
        issuer_dn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
    else:
        issuer_dn = subject
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_dn)
        .public_key(key.public_key())
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    elif eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
    return builder.sign(issuer_key or key, hashes.SHA256())


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def shift(moment: datetime, **delta: int) -> datetime:
    """Return `moment` moved by `timedelta(**delta)`."""
    return moment + timedelta(**delta)
