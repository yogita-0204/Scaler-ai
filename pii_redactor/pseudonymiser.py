"""Deterministic fake value generation."""

from __future__ import annotations
import hashlib
import random
import re
from faker import Faker
from .config import (
    CAT_EMAIL, CAT_PHONE, CAT_IP, CAT_CC, CAT_SSN,
    CAT_DOB, CAT_ADDRESS, CAT_PERSON, CAT_COMPANY,
    CAT_CIN, CAT_PAN, CAT_DIN, CAT_PINCODE,
    RANDOM_SEED,
)

_fake_in = Faker(["en_IN", "en_US"])
_fake_us = Faker("en_US")
Faker.seed(RANDOM_SEED)

_cache: dict[str, str] = {}


def _seed_from_value(value: str, salt: str = "") -> int:
    """Deterministic integer seed derived from the input value."""
    h = hashlib.md5((salt + value.lower().strip()).encode()).hexdigest()
    return int(h, 16) % (2**31)


def _seeded_fake(value: str, salt: str = "") -> random.Random:
    rng = random.Random(_seed_from_value(value, salt))
    return rng


def _fake_email(original: str) -> str:
    rng = _seeded_fake(original, "email")
    first_names = ["john", "jane", "alice", "michael", "priya", "rahul",
                   "anjali", "vikram", "neha", "arjun", "sunita", "deepak"]
    last_names  = ["doe", "smith", "jones", "sharma", "patel", "verma",
                   "singh", "kumar", "mehta", "gupta", "rao", "nair"]
    domains     = ["example.com", "mail-sample.org", "redacted-test.net",
                   "demo.in", "placeholder.co.in"]
    fn = rng.choice(first_names)
    ln = rng.choice(last_names)
    dm = rng.choice(domains)
    return f"{fn}.{ln}@{dm}"


def _fake_phone(original: str) -> str:
    rng = _seeded_fake(original, "phone")
    # Keep +91 prefix, replace digits
    prefix = "+91 "
    # 10-digit number starting with 7/8/9
    first_digit = rng.choice([7, 8, 9])
    rest = "".join(str(rng.randint(0, 9)) for _ in range(9))
    return f"{prefix}{first_digit}{rest}"


def _fake_ip(original: str) -> str:
    rng = _seeded_fake(original, "ip")
    return f"10.{rng.randint(0,254)}.{rng.randint(0,254)}.{rng.randint(1,254)}"


def _fake_cc(_original: str) -> str:
    # Use an explicit placeholder so downstream systems do not treat it as a
    # usable payment-card number.
    return "[REDACTED_CREDIT_CARD]"


def _fake_ssn(original: str) -> str:
    rng = _seeded_fake(original, "ssn")
    a = rng.randint(100, 899)
    b = rng.randint(10, 99)
    c = rng.randint(1000, 9999)
    return f"{a:03d}-{b:02d}-{c:04d}"


def _fake_dob(original: str) -> str:
    rng = _seeded_fake(original, "dob")
    year  = rng.randint(1950, 1985)
    month = rng.randint(1, 12)
    day   = rng.randint(1, 28)
    return f"{day:02d}/{month:02d}/{year}"


def _fake_address(_original: str) -> str:
    return "123, Redacted Lane, Sample Nagar, Demo City – 000000, India"


def _fake_person(original: str) -> str:
    rng = _seeded_fake(original, "person")
    first_names = [
        "Amit", "Priya", "Rahul", "Sunita", "Vikas", "Anjali",
        "Rajesh", "Kavita", "Suresh", "Meena", "Deepak", "Pooja",
        "Arun", "Neha", "Kiran", "Ravi", "Anita", "Sandeep",
    ]
    last_names = [
        "Sharma", "Patel", "Verma", "Singh", "Kumar", "Mehta",
        "Gupta", "Joshi", "Rao", "Nair", "Reddy", "Pillai",
        "Iyer", "Menon", "Bhat", "Shah", "Desai", "Malhotra",
    ]
    return f"{rng.choice(first_names)} {rng.choice(last_names)}"


def _fake_company(original: str) -> str:
    rng = _seeded_fake(original, "company")
    adjectives = ["Alpha", "Beta", "Horizon", "Pinnacle", "Apex",
                  "Summit", "Prime", "Global", "National", "Prestige"]
    nouns = ["Industries", "Solutions", "Ventures", "Enterprises",
             "Holdings", "Technologies", "Services", "Capital"]
    suffixes = ["Limited", "Pvt. Ltd.", "LLP"]
    return (f"{rng.choice(adjectives)} {rng.choice(nouns)} "
            f"{rng.choice(suffixes)}")


def _fake_cin(original: str) -> str:
    rng = _seeded_fake(original, "cin")
    prefix = rng.choice(["L", "U"])
    digits1 = "".join(str(rng.randint(0, 9)) for _ in range(5))
    state   = rng.choice(["MH", "DL", "KA", "GJ", "TN"])
    year    = str(rng.randint(1960, 2010))
    cat     = rng.choice(["PLC", "PTC"])
    digits2 = "".join(str(rng.randint(0, 9)) for _ in range(6))
    return f"{prefix}{digits1}{state}{year}{cat}{digits2}"


def _fake_pan(original: str) -> str:
    rng = _seeded_fake(original, "pan")
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    part1 = "".join(rng.choice(letters) for _ in range(5))
    digits = "".join(str(rng.randint(0, 9)) for _ in range(4))
    last   = rng.choice(letters)
    return f"{part1}{digits}{last}"


def _fake_din(original: str) -> str:
    rng = _seeded_fake(original, "din")
    return "".join(str(rng.randint(0, 9)) for _ in range(8))


def _fake_pincode(original: str) -> str:
    rng = _seeded_fake(original, "pincode")
    return f"{rng.randint(100000, 999999)}"


# Dispatch table
_GENERATORS: dict[str, callable] = {
    CAT_EMAIL:   _fake_email,
    CAT_PHONE:   _fake_phone,
    CAT_IP:      _fake_ip,
    CAT_CC:      _fake_cc,
    CAT_SSN:     _fake_ssn,
    CAT_DOB:     _fake_dob,
    CAT_ADDRESS: _fake_address,
    CAT_PERSON:  _fake_person,
    CAT_COMPANY: _fake_company,
    CAT_CIN:     _fake_cin,
    CAT_PAN:     _fake_pan,
    CAT_DIN:     _fake_din,
    CAT_PINCODE: _fake_pincode,
}


def get_replacement(category: str, original: str) -> str:
    """
    Return a deterministic fake replacement for `original`.
    The same original always yields the same replacement.
    """
    cache_key = f"{category}::{original.lower().strip()}"
    if cache_key in _cache:
        return _cache[cache_key]

    generator = _GENERATORS.get(category)
    if generator is None:
        fake = f"[REDACTED_{category}]"
    else:
        fake = generator(original)

    _cache[cache_key] = fake
    return fake


def clear_cache():
    """Reset the replacement cache (useful for testing)."""
    _cache.clear()
