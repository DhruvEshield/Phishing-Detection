"""
Tests for the shared email → normalized-text pipeline.

This normalization runs at BOTH training and inference time (see the module
docstring). These tests are the guardrail that keeps the two identical: they
pin down exactly what gets masked, stripped, and dropped, so a future edit that
re-opens a corpus-artifact leak (the v0.1.0 failure) fails here first.
"""
from __future__ import annotations

import text_normalize as tn


class TestStripHtml:
    def test_removes_tags(self):
        assert tn.strip_html("<p>hello <b>world</b></p>").split() == ["hello", "world"]

    def test_removes_style_and_script_blocks_including_content(self):
        html = "<style>.a{color:red}</style>keep<script>alert(1)</script>me"
        out = tn.strip_html(html)
        assert "color" not in out
        assert "alert" not in out
        assert "keep" in out and "me" in out

    def test_unescapes_entities(self):
        assert "&" in tn.strip_html("Tom &amp; Jerry")
        assert "<" in tn.strip_html("a &lt; b")


class TestNormalizeText:
    def test_empty_and_whitespace_return_empty(self):
        assert tn.normalize_text("") == ""
        assert tn.normalize_text("   \n\t ") == ""

    def test_lowercases(self):
        assert tn.normalize_text("URGENT Action") == "urgent action"

    def test_collapses_whitespace(self):
        assert tn.normalize_text("a\n\n  b\t c") == "a b c"

    def test_url_is_masked_to_placeholder(self):
        for raw in ("http://evil.example/verify", "https://a.b/c?d=1", "www.evil.com/x"):
            out = tn.normalize_text(f"click {raw} now")
            assert "url" in out.split()
            # the identity of the link must be gone…
            assert "evil" not in out and "verify" not in out
            # …but the *fact* that a link exists is kept as a weak signal.
            assert out.split() == ["click", "url", "now"]

    def test_email_is_masked_to_placeholder(self):
        out = tn.normalize_text("reply to alice@company.com please")
        assert out.split() == ["reply", "to", "email", "please"]

    def test_honeypot_dotless_address_is_masked(self):
        # `phishing@pot` was a literal label leak — the dotless domain must
        # still be caught by the email regex.
        out = tn.normalize_text("delivered to phishing@pot header")
        assert "phishing@pot" not in out
        assert "email" in out.split()

    def test_numbers_dates_times_ips_are_masked(self):
        for raw in ("2024", "12:30", "01/02/2023", "192.168.1.1"):
            out = tn.normalize_text(f"value {raw} end")
            assert "num" in out.split(), raw
            assert raw not in out, raw

    def test_leakage_stopwords_are_dropped(self):
        # enron/vince = Enron corpus identity; the rest = MIME/charset words that
        # survive HTML-stripping in one class only. None are content.
        for word in ("enron", "vince", "utf", "iso", "8859", "quoted",
                     "printable", "charset", "mime", "multipart", "boundary", "nbsp"):
            out = tn.normalize_text(f"real content {word} more content")
            assert word not in out.split(), word
            assert "content" in out.split()

    def test_html_is_stripped_and_href_identity_removed(self):
        # The link lives in the href *attribute*, which strip_html removes with
        # the tag — so only the visible anchor text survives. The specific host
        # (x.co) must not leak through.
        raw = '<html><body>Verify at <a href="http://x.co">here</a></body></html>'
        out = tn.normalize_text(raw)
        assert "<" not in out and "href" not in out
        assert "x.co" not in out
        assert out.split() == ["verify", "at", "here"]

    def test_visible_url_in_body_is_masked(self):
        # A URL in the visible text (not an attribute) is masked to the placeholder.
        out = tn.normalize_text("<p>Go to http://evil.co/verify today</p>")
        assert "url" in out.split()
        assert "evil" not in out

    def test_realistic_phishing_body_reduces_to_content_words(self):
        raw = ("Your account will be suspended. Verify your password now: "
               "http://login-secure.xyz/verify — sent 2024-01-02")
        out = tn.normalize_text(raw)
        assert "account" in out and "suspended" in out and "password" in out
        assert "url" in out.split() and "num" in out.split()
        assert "login-secure" not in out


class TestFromEmlBytes:
    def _eml(self, subject: str, body: str) -> bytes:
        return (
            f"From: Attacker <attacker@evil.example>\r\n"
            f"To: victim@company.com\r\n"
            f"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
            f"Received: from mx.evil.example\r\n"
            f"Subject: {subject}\r\n"
            f"\r\n"
            f"{body}\r\n"
        ).encode()

    def test_keeps_subject_and_body_drops_headers(self):
        out = tn.from_eml_bytes(self._eml("Reset your password", "Click the secure link"))
        assert "reset" in out and "password" in out
        assert "click" in out and "secure" in out
        # header identities must not survive
        assert "attacker" not in out
        assert "received" not in out
        assert "mx" not in out

    def test_multipart_html_and_plain_bodies_are_extracted(self):
        raw = (
            "Subject: Invoice\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/alternative; boundary="B"\r\n'
            "\r\n"
            "--B\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "plaintext part\r\n"
            "--B\r\n"
            "Content-Type: text/html\r\n\r\n"
            "<p>html part</p>\r\n"
            "--B--\r\n"
        ).encode()
        out = tn.from_eml_bytes(raw)
        assert "plaintext" in out and "part" in out
        assert "html" in out
        assert "<p>" not in out
        # 'multipart'/'boundary' are leakage stopwords — must be gone.
        assert "multipart" not in out.split() and "boundary" not in out.split()

    def test_garbage_bytes_do_not_raise(self):
        # Never throw on malformed input — inference must stay resilient.
        assert isinstance(tn.from_eml_bytes(b"\xff\xfe not an email"), str)


class TestFromEmlFile:
    def test_missing_file_returns_empty_string(self):
        assert tn.from_eml_file("/no/such/file.eml") == ""

    def test_reads_and_normalizes(self, tmp_path):
        p = tmp_path / "m.eml"
        p.write_bytes(b"Subject: Hi\r\n\r\nHello there\r\n")
        out = tn.from_eml_file(p)
        assert "hi" in out and "hello" in out


class TestFromEnronTxt:
    def test_drops_date_line_and_subject_label_keeps_values(self, tmp_path):
        p = tmp_path / "e.txt"
        p.write_text(
            "Subject: Q3 numbers\n"
            "Date: 2001-05-01 00:00:00\n"
            "\n"
            "Please review the attached spreadsheet.\n",
            encoding="utf-8",
        )
        out = tn.from_enron_txt(p)
        # subject value + body survive; the literal 'subject:'/'date:' labels do not
        assert "numbers" in out and "spreadsheet" in out
        assert "date" not in out.split()
        assert "subject" not in out.split()

    def test_missing_file_returns_empty_string(self):
        assert tn.from_enron_txt("/no/such/file.txt") == ""
