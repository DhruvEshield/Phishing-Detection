import pytest
from app.detectors.url import _extract_anchor_pairs

def test_extract_simple_anchor():
    html = '<p>Click <a href="https://example.com">here</a> to login.</p>'
    pairs = _extract_anchor_pairs(html)
    assert len(pairs) == 1
    assert pairs[0]["href"] == "https://example.com"
    assert pairs[0]["anchor_text"] == "here"

def test_extract_nested_tags():
    html = '<a href="https://evil.com">Click <b>here</b> for a <i>free</i> gift!</a>'
    pairs = _extract_anchor_pairs(html)
    assert len(pairs) == 1
    assert pairs[0]["href"] == "https://evil.com"
    assert pairs[0]["anchor_text"] == "Click here for a free gift!"

def test_extract_multiple_anchors():
    html = """
    <a href="https://a.com">Link A</a>
    Some text
    <a class="btn" href='http://b.org'>Link B</a>
    """
    pairs = _extract_anchor_pairs(html)
    assert len(pairs) == 2
    assert pairs[0]["href"] == "https://a.com"
    assert pairs[0]["anchor_text"] == "Link A"
    assert pairs[1]["href"] == "http://b.org"
    assert pairs[1]["anchor_text"] == "Link B"

def test_anchor_with_no_href():
    html = '<a>Just an anchor</a> <a name="top">Top</a>'
    pairs = _extract_anchor_pairs(html)
    assert len(pairs) == 0

def test_anchor_with_empty_text():
    html = '<a href="https://empty.com">   </a> <a href="https://img.com"><img src="x.png"></a>'
    pairs = _extract_anchor_pairs(html)
    assert len(pairs) == 0

def test_malformed_html():
    html = '<a href="https://bad.com">Unclosed anchor'
    pairs = _extract_anchor_pairs(html)
    assert len(pairs) == 0

from app.detectors.url import _check_anchor_mismatch

def test_anchor_brand_mismatch():
    pairs = [{"href": "https://evil.com/login", "anchor_text": "Login to Amazon now"}]
    flags = _check_anchor_mismatch(pairs)
    assert len(flags) == 1
    assert flags[0] == "anchor_brand_mismatch:amazon(text_claims:amazon,href_domain:evil.com)"

def test_anchor_domain_mismatch():
    pairs = [{"href": "https://evil.com/login", "anchor_text": "Please visit amazon.com for help"}]
    flags = _check_anchor_mismatch(pairs)
    # Could hit both Case A (amazon) and Case B (amazon.com != evil.com).
    assert any("anchor_text_href_mismatch:amazon.com!=evil.com" in f for f in flags)

def test_anchor_text_href_match():
    pairs = [{"href": "https://amazon.com/login", "anchor_text": "Login to Amazon"}]
    flags = _check_anchor_mismatch(pairs)
    assert len(flags) == 0

def test_anchor_no_brand_no_domain():
    pairs = [{"href": "https://evil.com/login", "anchor_text": "Click here to view document"}]
    flags = _check_anchor_mismatch(pairs)
    assert len(flags) == 0
