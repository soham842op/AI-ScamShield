"""Fixed brand list for lookalike detection.

The list is finite on purpose: a brand that is not here is not covered. Changing
the list, the distance limits or the confusable map bumps URL_RULES_VERSION.
"""

from dataclasses import dataclass

_AMAZON_COUNTRY = (
    "co.za",
    "com.sg",
    "ie",
    "co.uk",
    "de",
    "fr",
    "it",
    "es",
    "ca",
    "com.au",
    "co.jp",
    "in",
    "com.br",
    "com.mx",
    "nl",
    "se",
    "pl",
    "sg",
    "ae",
    "sa",
    "com.tr",
)
_GOOGLE_COUNTRY = (
    "ie",
    "pl",
    "com.mx",
    "co.za",
    "se",
    "com.sg",
    "co.nz",
    "co.uk",
    "de",
    "fr",
    "ca",
    "com.au",
    "co.in",
    "co.jp",
    "es",
    "it",
    "com.br",
    "nl",
)


@dataclass(frozen=True, slots=True)
class Brand:
    # Lowercase ASCII label, for example "paypal".
    label: str
    # Registrable domains that really belong to the brand.
    domains: frozenset[str]


def _brand(label: str, *domains: str) -> Brand:
    return Brand(label=label, domains=frozenset(domains))


BRANDS: tuple[Brand, ...] = (
    _brand("paypal", "paypal.com", "paypal.me", "paypal.co.uk", "paypal.de", "paypal.fr"),
    _brand("apple", "apple.com", "icloud.com", "apple.news"),
    _brand(
        "amazon",
        "amazon.com",
        "amazonaws.com",
        "amazon.jobs",
        *(f"amazon.{tld}" for tld in _AMAZON_COUNTRY),
    ),
    _brand("microsoft", "microsoft.com", "live.com", "outlook.com", "office.com"),
    _brand(
        "google",
        "google.com",
        "gmail.com",
        "googlemail.com",
        *(f"google.{tld}" for tld in _GOOGLE_COUNTRY),
    ),
    _brand("netflix", "netflix.com"),
    _brand("facebook", "facebook.com", "fb.com"),
    _brand("instagram", "instagram.com"),
    _brand("whatsapp", "whatsapp.com", "whatsapp.net"),
    _brand("dhl", "dhl.com", "dhl.de", "dhl.co.uk", "dhl.fr"),
    _brand("fedex", "fedex.com"),
    _brand("ups", "ups.com"),
    _brand("usps", "usps.com"),
    _brand("chase", "chase.com"),
    _brand("wellsfargo", "wellsfargo.com"),
    _brand("bankofamerica", "bankofamerica.com"),
    _brand("hsbc", "hsbc.com", "hsbc.co.uk"),
    _brand("coinbase", "coinbase.com"),
    _brand("binance", "binance.com"),
    _brand("linkedin", "linkedin.com"),
)

REAL_DOMAINS: frozenset[str] = frozenset(d for brand in BRANDS for d in brand.domains)
BRAND_LABELS: frozenset[str] = frozenset(brand.label for brand in BRANDS)

# Single characters (and Cyrillic/Greek lookalikes) folded to a Latin letter.
_CONFUSABLES = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "i": "l",
    # Cyrillic
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0443": "y",
    "\u0455": "s",
    "\u0456": "l",
    "\u0458": "j",
    "\u0501": "d",
    "\u04bb": "h",
    # Greek
    "\u03b1": "a",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03bd": "v",
    "\u03b9": "l",
    "\u03ba": "k",
    "\u03c4": "t",
    # Latin letters outside ASCII that look like ASCII ones
    "\u04cf": "l",
    "\u0475": "v",
    "\u04af": "y",
    "\u051b": "q",
    "\u051d": "w",
    "\u03c5": "u",
    "\u0251": "a",
    "\u0261": "g",
    "\u0131": "l",
}


def skeleton(label: str) -> str:
    """Fold look-alike characters so that, for example, "paypa1" and "paypal" match."""
    folded = "".join(_CONFUSABLES.get(ch, ch) for ch in label.lower())
    return folded.replace("rn", "m").replace("vv", "w")


_BRAND_SKELETONS = {brand.label: skeleton(brand.label) for brand in BRANDS}


def max_distance(brand_label: str) -> int:
    """Edit distance allowed for a brand label.

    Short labels get no fuzzy match, only the confusable skeleton, because
    ordinary words sit one edit away from them ("apply", "phase").
    """
    if len(brand_label) <= 5:
        return 0
    return 2 if len(brand_label) >= 8 else 1


def damerau_levenshtein(a: str, b: str) -> int:
    """Edit distance with adjacent transposition (optimal string alignment)."""
    if a == b:
        return 0
    rows = len(a) + 1
    cols = len(b) + 1
    d = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        d[i][0] = i
    for j in range(cols):
        d[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def label_matches_brand(label: str, brand: Brand) -> bool:
    """Whole-label match: skeleton equality or a small edit distance."""
    if label.lower() in NEAR_BRAND_WORDS:
        return False
    if skeleton(label) == _BRAND_SKELETONS[brand.label]:
        return True
    limit = max_distance(brand.label)
    if limit == 0 or abs(len(label) - len(brand.label)) > limit:
        return False
    return damerau_levenshtein(label.lower(), brand.label) <= limit


# Everyday words that sit within edit distance of a brand label.
NEAR_BRAND_WORDS: frozenset[str] = frozenset(
    {"finance", "goggle", "goggles", "whatsup", "binary", "chases", "applet"}
)

# A host that also carries one of these words reads as a login or payment lure.
PHISHING_KEYWORDS: frozenset[str] = frozenset(
    {
        "login",
        "signin",
        "verify",
        "secure",
        "account",
        "update",
        "support",
        "billing",
        "wallet",
        "payment",
        "confirm",
    }
)

_TLD_LIKE_LABELS = frozenset({"com", "net", "org", "co", "gov", "edu"})

# Hyphen tokens and subdomain labels of shorter brand names are common words
# ("pop-ups", "big-apple-pizza"), so they count only with a phishing keyword.
MIN_TOKEN_BRAND_LENGTH = 7
MIN_SUBDOMAIN_BRAND_LENGTH = 6


def has_phishing_keyword(host: str) -> bool:
    return any(
        token in PHISHING_KEYWORDS for label in host.split(".") for token in label.split("-")
    )


def is_tld_like(label: str) -> bool:
    return label in _TLD_LIKE_LABELS


def token_matches_brand(token: str, brand: Brand) -> bool:
    """A hyphen token or subdomain label that is the brand name, or its skeleton."""
    return token.lower() == brand.label or skeleton(token) == _BRAND_SKELETONS[brand.label]
