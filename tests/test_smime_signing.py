import datetime
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import smime_email


def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_public_key = ca_private_key.public_key()
    return ca_private_key, ca_public_key


def generate_ca_certificate(
    ca_private_key: rsa.RSAPrivateKey, ca_public_key: rsa.RSAPublicKey
) -> tuple[x509.Certificate, x509.Name]:
    ca_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Root CA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key),
            critical=False,
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
        .sign(ca_private_key, hashes.SHA256())
    )
    return ca_cert, ca_name


def generate_intermediate_certificate(
    intermediate_public_key: rsa.RSAPublicKey,
    ca_private_key: rsa.RSAPrivateKey,
    ca_public_key: rsa.RSAPublicKey,
    ca_name: x509.Name,
) -> tuple[x509.Certificate, x509.Name]:
    # Generate a certificate for the intermediate authority
    intermediate_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Intermediate CA"),
        ]
    )
    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(intermediate_name)
        .issuer_name(ca_name)
        .public_key(intermediate_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(ca_public_key)
            ),
            critical=False,
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
        .sign(ca_private_key, hashes.SHA256())
    )
    return intermediate_cert, intermediate_name


def generate_email_certificate(
    email_public_key: rsa.RSAPublicKey,
    intermediate_private_key: rsa.RSAPrivateKey,
    intermediate_public_key: rsa.RSAPublicKey,
    intermediate_name: x509.Name,
) -> x509.Certificate:
    # Generate a certificate for the email address
    email_address = "myemail@example.com"
    name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "TestMailer"),
            x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, email_address),
        ]
    )
    email_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(intermediate_name)
        .public_key(email_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(email_public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(intermediate_public_key)
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email_address)]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ]
            ),
            critical=False,
        )
        .sign(intermediate_private_key, hashes.SHA256())
    )
    return email_cert


def generate_certificates() -> (
    tuple[rsa.RSAPrivateKey, x509.Certificate, x509.Certificate, x509.Certificate]
):
    ca_private_key, ca_public_key = generate_rsa_keypair()
    intermediate_private_key, intermediate_public_key = generate_rsa_keypair()
    email_private_key, email_public_key = generate_rsa_keypair()
    ca_certificate, ca_name = generate_ca_certificate(ca_private_key, ca_public_key)
    intermediate_certificate, intermediate_name = generate_intermediate_certificate(
        intermediate_public_key, ca_private_key, ca_public_key, ca_name
    )
    email_certificate = generate_email_certificate(
        email_public_key,
        intermediate_private_key,
        intermediate_public_key,
        intermediate_name,
    )
    return (
        email_private_key,
        email_certificate,
        ca_certificate,
        intermediate_certificate,
    )


def test_sign_smime_produces_valid_payload() -> None:
    (
        email_private_key,
        email_certificate,
        ca_certificate,
        intermediate_certificate,
    ) = generate_certificates()
    message_str = "test message"
    smime_content = smime_email.get_smime_attachment_content(
        bytes(message_str, "utf-8"),
        email_private_key,
        email_certificate,
        [intermediate_certificate, ca_certificate],
    )
    # Combine the intermediate certificate, and root certificate into a list
    cert_chain = [intermediate_certificate, ca_certificate]

    # Concatenate the PEM-encoded certificates into a single PEM file
    full_chain_pem = b"".join(
        [cert.public_bytes(serialization.Encoding.PEM) for cert in cert_chain]
    )

    # Write the full chain to disk
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        full_chain_path = tmpdir_path / "full_chain.pem"
        email_path = tmpdir_path / "email.eml"
        cert_path = tmpdir_path / "cert.pem"
        out_path = tmpdir_path / "output.txt"
        with open(full_chain_path, "wb") as f:
            f.write(full_chain_pem)
        with open(cert_path, "wb") as f:
            f.write(email_certificate.public_bytes(serialization.Encoding.PEM))
        with open(email_path, "wb") as f:
            f.write(smime_content)
        # use raw openssl to verify as cryptography can't do it, yet: https://github.com/pyca/cryptography/issues/2381
        subprocess.check_call(
            [
                "openssl",
                "smime",
                "-verify",
                "-in",
                str(email_path),
                "-CAfile",
                str(full_chain_path),
                "-out",
                str(out_path),
            ]
        )
        with open(out_path, "r") as f:
            assert f.read() == message_str
