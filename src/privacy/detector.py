from dataclasses import dataclass
import re

@dataclass(frozen=True)
class Entity:
    entity_type: str; value: str; start: int; end: int; placeholder: str = ""

# ISO 13616 country lengths are deliberately not hard-coded: the registry can
# evolve and the modulo-97 check is the authoritative checksum here. Candidate
# lengths remain bounded to the ISO 13616 range (15..34 characters).
_IBAN_LENGTHS = {
    "AD":24,"AE":23,"AL":28,"AT":20,"AZ":28,"BA":20,"BE":16,"BG":22,
    "BH":22,"BI":16,"BR":29,"BY":28,"CH":21,"CR":22,"CY":28,"CZ":24,
    "DE":22,"DK":18,"DO":28,"EE":20,"EG":29,"ES":24,"FI":18,"FK":18,
    "FO":18,"FR":27,"GB":22,"GE":22,"GI":23,"GL":18,"GR":27,"GT":28,
    "HN":28,"HR":21,"HU":28,"IE":22,"IL":23,"IQ":23,"IS":26,"IT":27,
    "JO":30,"KW":30,"KZ":20,"LB":28,"LC":32,"LI":21,"LT":20,"LU":20,
    "LV":21,"LY":25,"MC":27,"MD":24,"ME":22,"MK":19,"MN":20,"MR":27,
    "MT":31,"MU":30,"MZ":25,"NI":32,"NL":18,"NO":15,"PK":24,"PL":28,
    "PS":29,"PT":25,"QA":29,"RO":24,"RS":22,"RU":33,"SA":24,"SC":31,
    "SD":18,"SE":24,"SI":19,"SK":24,"SM":27,"SN":28,"SO":23,"ST":25,
    "SV":28,"TL":23,"TN":24,"TR":26,"UA":29,"VA":22,"VG":24,"XK":20,
}
_IBAN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2}\d{2}(?:[A-Za-z0-9][ -]?){10,34}(?![A-Za-z0-9])")
_TAX=re.compile(r"(?<!\d)\d{11}(?!\d)\b")
_EMAIL=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# E.164 is deliberately strict: a plus sign and at most 15 digits. Existing
# conservative German/Austrian local formats remain supported for compatibility.
_E164_PHONE=re.compile(r"(?<!\w)\+[1-9]\d{1,14}(?!\w)")
_FORMATTED_INTL_PHONE=re.compile(r"(?<!\w)\+[1-9](?:[\s()./-]?\d){5,18}(?!\w)")
_LOCAL_PHONE=re.compile(r"(?<!\w)(?:0049|0043|0)[\s./-]?\d(?:[\s./-]?\d){6,14}(?!\w)")
_PLATE=re.compile(r"\b[A-ZÄÖÜ]{1,3}-[A-Z]{1,2}\s?\d{1,4}[EH]?\b", re.I)
_PERSONAL=re.compile(r"\b[CFGHJKLMNPRTVWXYZ]\d{8}\b", re.I)
_NAME=re.compile(r"\b(?:Herr|Frau|Mr\.?|Ms\.?|Mrs\.?|M\.?|Mme\.?|Monsieur|Madame|Sig\.?|Sig\.ra|Signor|Signora|Sr\.?|Sra\.?|Señor|Señora)\s+[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ]+(?:\s+[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ]+)?\b")

# DLP secret patterns are static, bounded recognizers. They never log or
# persist the matched value outside the short-lived placeholder vault.
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_OPENAI_KEY = re.compile(r"sk-[a-zA-Z0-9_-]{20,}")
_ANTHROPIC_KEY = re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}")
_GITHUB_TOKEN = re.compile(r"ghp_[a-zA-Z0-9]{36}")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PRIVATE)(?: PRIVATE)? KEY-----")
_JWT_TOKEN = re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")
_CONNECTION_STRING = re.compile(r"(?:postgres|mysql|mongodb|redis):\/\/[^\s]+")
MAX_DETECTED_ENTITIES = 1_000

_SECRET_PATTERNS = [
    ("AWS_KEY", _AWS_KEY), ("ANTHROPIC_KEY", _ANTHROPIC_KEY),
    ("OPENAI_KEY", _OPENAI_KEY), ("GITHUB_TOKEN", _GITHUB_TOKEN),
    ("PRIVATE_KEY", _PRIVATE_KEY), ("JWT_TOKEN", _JWT_TOKEN),
    ("CONNECTION_STRING", _CONNECTION_STRING),
]

class RegexDetector:
    mode="regex_fallback"
    languages=("de", "en", "fr", "it", "es")
    def __init__(self, custom_patterns: dict[str, str] | None = None):
        self.custom_patterns = {k: re.compile(v) for k, v in (custom_patterns or {}).items()}
    def detect(self,text: str, language: str="de") -> list[Entity]:
        found: list[Entity] = []
        patterns = list(self.custom_patterns.items()) + [
            ("EMAIL_ADDRESS",_EMAIL), ("IBAN_CODE",_IBAN), ("GERMAN_TAX_ID",_TAX), ("PHONE_NUMBER",_E164_PHONE),
            ("PHONE_NUMBER",_LOCAL_PHONE), ("GERMAN_LICENSE_PLATE",_PLATE),
            ("PERSONAL_ID",_PERSONAL), ("PERSON",_NAME),
        ] + _SECRET_PATTERNS
        def add(entity: Entity) -> None:
            found.append(entity)
            if len(found) > MAX_DETECTED_ENTITIES:
                raise ValueError("too many detected entities")

        for typ,rx in patterns:
            for m in rx.finditer(text):
                value=m.group(); clean=re.sub(r"[ .-]", "", value)
                if typ=="IBAN_CODE" and not valid_iban(clean): continue
                if typ=="GERMAN_TAX_ID" and not valid_tax_id(clean): continue
                add(Entity(typ,value,m.start(),m.end()))
        for rx in (_FORMATTED_INTL_PHONE,):
            for m in rx.finditer(text):
                value = m.group()
                if 8 <= len(re.sub(r"\D", "", value)) <= 15:
                    add(Entity("PHONE_NUMBER", value, m.start(), m.end()))
        # Longest match, then left-to-right; overlapping detector hits are discarded.
        out: list[Entity] = []
        for e in sorted(found,key=lambda x:(-(x.end-x.start),x.start)):
            if not any(e.start < x.end and x.start < e.end for x in out): out.append(e)
        return sorted(out,key=lambda x:x.start)

def valid_iban(v:str)->bool:
    value = re.sub(r"[ \-]", "", v).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", value): return False
    if len(value) != _IBAN_LENGTHS.get(value[:2], -1): return False
    moved=value[4:]+value[:4]
    nums=''.join(str(ord(c)-55) if c.isalpha() else c for c in moved)
    return int(nums)%97==1

def valid_tax_id(v:str)->bool:
    if len(v)!=11 or len(set(v))==1: return False
    digits=list(map(int,v)); check=digits[-1]; prod=10
    for d in digits[:-1]:
        val=(d+prod)%10; val=10 if val==0 else val; prod=(2*val)%11
    return (11-prod)%10 == check

def assign_placeholders(entities: list[Entity]) -> list[Entity]:
    by_type: dict[str, int] = {}; by_value: dict[tuple[str, str], str] = {}; out: list[Entity] = []
    for e in entities:
        key=(e.entity_type,e.value)
        if key not in by_value: by_value[key]=f"<{e.entity_type}_{by_type.get(e.entity_type,0)}>"; by_type[e.entity_type]=by_type.get(e.entity_type,0)+1
        out.append(Entity(e.entity_type,e.value,e.start,e.end,by_value[key]))
    return out

class PresidioDetector(RegexDetector):
    """Use an explicitly supplied Presidio analyzer; never download models."""
    def __init__(self, analyzer=None, custom_patterns=None, presidio_languages=None):
        super().__init__(custom_patterns)
        self.analyzer = analyzer
        self.presidio_languages = set(presidio_languages or self.languages)
        self.mode = "presidio" if analyzer is not None else "regex_fallback"
    def detect(self, text: str, language: str = "de") -> list[Entity]:
        if self.analyzer is None or language not in self.presidio_languages:
            return super().detect(text, language)
        try:
            results = self.analyzer.analyze(text=text, language=language)
        except Exception:
            return super().detect(text, language)
        accepted = [result for result in results if result.score >= 0.5]
        if len(accepted) > MAX_DETECTED_ENTITIES:
            raise ValueError("too many detected entities")
        entities = [Entity(result.entity_type, text[result.start:result.end], result.start, result.end) for result in accepted]
        entities.extend(super().detect(text, language))
        if len(entities) > MAX_DETECTED_ENTITIES:
            raise ValueError("too many detected entities")
        out: list[Entity] = []
        for e in sorted(entities, key=lambda x: (-(x.end-x.start), x.start)):
            if not any(e.start < x.end and x.start < e.end for x in out): out.append(e)
        return sorted(out, key=lambda x: x.start)
    def mode_for(self, language: str) -> str:
        return "presidio" if self.analyzer is not None and language in self.presidio_languages else "regex_fallback"
