"""Brand intelligence module.

Replaces manual Levenshtein-based brand lookalike checks with dnstwist-generated
permutations (homoglyphs, omissions, additions, etc.). Caches permutations in Redis
to avoid re-running the fuzzer for known brands. Safe-fail by design.
"""
from __future__ import annotations

import json
import structlog
import dnstwist
from typing import Optional
from dataclasses import dataclass

from app.data.brand_seeds import BRAND_SEEDS

log = structlog.get_logger()

@dataclass
class BrandMatch:
    domain: str
    matched_brand: str
    permutation_type: str
    matched_domain: str

def _get_redis_client():
    from app.config import get_settings
    import redis
    settings = get_settings()
    return redis.from_url(settings.redis_url, decode_responses=True)

def get_brand_permutations(brand_domain: str) -> list[dict]:
    """
    Generate dnstwist permutations for a single brand domain.
    No live DNS checking. Caches in Redis for 7 days.
    Returns list of dicts: {"fuzzer": str, "domain": str}
    """
    cache_key = f"dnstwist:{brand_domain}"
    try:
        r = _get_redis_client()
        cached = r.get(cache_key)
        if cached:
            return json.loads(cached)
    except Exception as exc:
        log.warning("brand_intel.redis_cache_read_error", error=str(exc))
        r = None

    try:
        fuzzer = dnstwist.Fuzzer(brand_domain)
        fuzzer.generate()
        permutations = [{"fuzzer": p["fuzzer"], "domain": p["domain"]} for p in fuzzer.permutations()]
        
        if r:
            try:
                r.setex(cache_key, 7 * 86400, json.dumps(permutations))
            except Exception as exc:
                log.warning("brand_intel.redis_cache_write_error", error=str(exc))
                
        return permutations
    except Exception as exc:
        log.warning("brand_intel.generation_error", brand_domain=brand_domain, error=str(exc))
        return []

def check_domain_against_brands(domain: str) -> Optional[BrandMatch]:
    """
    Check if a domain matches any generated permutations of our brand seeds.
    Exact match after normalizing case. Returns BrandMatch or None.
    Safe-fail: never raise, return None on error.
    """
    try:
        norm_domain = domain.strip().lower()
        if not norm_domain:
            return None
            
        for brand_name, brand_domain in BRAND_SEEDS.items():
            perms = get_brand_permutations(brand_domain)
            for p in perms:
                if p["domain"] == norm_domain:
                    return BrandMatch(
                        domain=norm_domain,
                        matched_brand=brand_name,
                        permutation_type=p["fuzzer"],
                        matched_domain=p["domain"]
                    )
        return None
    except Exception as exc:
        log.warning("brand_intel.check_error", domain=domain, error=str(exc))
        return None
