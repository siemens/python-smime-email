import cryptography
import cryptography.hazmat
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.serialization.pkcs7
import cryptography.x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    PKCS7Options,
    PKCS7SignatureBuilder,
    PKCS7PrivateKeyTypes,
)
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.base import Certificate


def load_certificates(cert_path: str) -> list[Certificate]:
    with open(cert_path, "r") as f:
        delimiter = "-----END CERTIFICATE-----"
        split_content = f.read().split(delimiter)
        split_content = split_content[: len(split_content) - 1]
        return [
            cryptography.x509.load_pem_x509_certificate(
                bytes(cert + delimiter, "utf-8")
            )
            for cert in split_content
        ]


def load_key(key_path: str) -> PrivateKeyTypes:
    with open(key_path, "rb") as f:
        return cryptography.hazmat.primitives.serialization.load_pem_private_key(
            f.read(),
            None,
        )


def add_headers(headers: dict[str, str], message: bytes) -> bytes:
    content = message.decode("utf-8")
    for key, value in headers.items():
        content = f"{key}: {value}\n{content}"
    return content.encode("utf-8")


def get_smime_attachment_content(
    data: bytes,
    key: PKCS7PrivateKeyTypes,
    cert: Certificate,
    ca: list[Certificate],
) -> bytes:
    build = (
        PKCS7SignatureBuilder()
        .set_data(data)
        .add_signer(cert, key, cryptography.hazmat.primitives.hashes.SHA512())
    )
    for c in ca:
        build = build.add_certificate(c)
    return build.sign(
        Encoding.SMIME,
        options=[PKCS7Options.DetachedSignature],
    )
