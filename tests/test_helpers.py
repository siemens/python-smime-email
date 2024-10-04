import pytest

import smime_email


@pytest.mark.parametrize(
    "header_dict,message,result",
    (
        (  # one header
            {"Content-Type": "text/html"},
            b"Content",
            b"Content-Type: text/html\nContent",
        ),
        (  # two headers
            {
                "Content-Type": "text/html",
                "Subject": "Hello. The subject is never signed!",
            },
            b"Content",
            b"Subject: Hello. The subject is never signed!\nContent-Type: text/html\nContent",
        ),
        (  # no headers
            {},
            b"Content",
            b"Content",
        ),
    ),
)
def test_add_headers(
    header_dict: dict[str, str], message: bytes, result: bytes
) -> None:
    assert smime_email.add_headers(header_dict, message) == result
