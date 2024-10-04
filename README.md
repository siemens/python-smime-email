# python-smime-email

<a href="https://pypi.org/project/smime-email/"><img alt="PyPI" src="https://img.shields.io/pypi/v/smime-email"></a>
<a href="https://pepy.tech/project/smime-email"><img alt="Downloads" src="https://pepy.tech/badge/smime-email"></a>

Generate x509 SMIME signed emails with ease!

## Usage

1. Generate the email raw content

    ```python
    import smime_email

    data = b"Hello!"
    SMIME_KEY = smime_email.load_key("key_path.pem")
    SMIME_INTERMEDIATE = smime_email.load_certificates("intermediate_path.pem")
    SMIME_CERT = smime_email.load_certificates("cert_path.pem")[0]
    email_raw_bytes = smime_email.get_smime_attachment_content(data, SMIME_KEY, SMIME_INTERMEDIATE, SMIME_CERT)
    ```

1. Send it using any email library you like. Here is an example as Django email backend

    ```python
    email_raw_bytes = smime_email.get_smime_attachment_content(data, SMIME_KEY, SMIME_INTERMEDIATE, SMIME_CERT)
    # ...
    class EmailBackend(BaseEmailBackend):
        def send_messages(self, message) -> int:
            with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
                server.sendmail(message.from_email, message.to, email_raw_bytes)
            return 1
    ```

## Development

The code is formatted with **ruff** and checked with various linters.
To run the whole linting and formatting process, run `poetry run poe all`.

## License

Code and documentation copyright 2024 Siemens AG.

See [LICENSE.md](LICENSE.md).
