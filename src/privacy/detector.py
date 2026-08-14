from dataclasses import dataclass
import re
from typing import Iterable

@dataclass(frozen=True)
class Entity:
    entity_type: str; value: str; start: int; end: int; placeholder: str = ""

_IBAN=re.compile(r"\bDE\d{2}(?:\s?\d{4}){4}\s?\d{2}\b", re.I)
_TAX=re.compile(r"\b\d{11}\b")
_EMAIL=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE=re.compile(r"(?<!\w)(?:\+49|0049|\+43|0043|0)[\s./-]?\d(?:[\s./-]?\d){6,14}(?!\w)")
_PLATE=re.compile(r"\b[A-ZÄÖÜ]{1,3}-[A-Z]{1,2}\s?\d{1,4}[EH]?\b", re.I)
_PERSONAL=re.compile(r"\b[CFGHJKLMNPRTVWXYZ]\d{8}\b", re.I)
_NAME=re.compile(r"\b(?:Herr|Frau)\s+[A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?\b")

class RegexDetector:
    mode="regex_fallback"
    def __init__(self, custom_patterns: dict[str, str] | None = None):
        self.custom_patterns = {k: re.compile(v) for k, v in (custom_patterns or {}).items()}
    def detect(self,text: str, language: str="de") -> list[Entity]:
        found=[]
        for typ,rx in list(self.custom_patterns.items()) + [("EMAIL_ADDRESS",_EMAIL),("IBAN_CODE",_IBAN),("GERMAN_TAX_ID",_TAX),("PHONE_NUMBER",_PHONE),("GERMAN_LICENSE_PLATE",_PLATE),("PERSONAL_ID",_PERSONAL),("PERSON",_NAME)]:
            for m in rx.finditer(text):
                value=m.group(); clean=re.sub(r"[ .-]", "", value)
                if typ=="IBAN_CODE" and not valid_iban(clean): continue
                if typ=="GERMAN_TAX_ID" and not valid_tax_id(clean): continue
                found.append(Entity(typ,value,m.start(),m.end()))
        # Longest match, then left-to-right; overlapping detector hits are discarded.
        out=[]
        for e in sorted(found,key=lambda x:(-(x.end-x.start),x.start)):
            if not any(e.start < x.end and x.start < e.end for x in out): out.append(e)
        return sorted(out,key=lambda x:x.start)

def valid_iban(v:str)->bool:
    if not re.fullmatch(r"DE\d{20}",v,re.I): return False
    moved=v[4:]+v[:4]; nums=''.join(str(ord(c.upper())-55) if c.isalpha() else c for c in moved)
    return int(nums)%97==1

def valid_tax_id(v:str)->bool:
    if len(v)!=11 or len(set(v))==1: return False
    digits=list(map(int,v)); check=digits[-1]; prod=10
    for d in digits[:-1]:
        val=(d+prod)%10; val=10 if val==0 else val; prod=(2*val)%11
    return (11-prod)%10 == check

def assign_placeholders(entities: list[Entity]) -> list[Entity]:
    by_type={}; by_value={}; out=[]
    for e in entities:
        key=(e.entity_type,e.value)
        if key not in by_value: by_value[key]=f"<{e.entity_type}_{by_type.get(e.entity_type,0)}>"; by_type[e.entity_type]=by_type.get(e.entity_type,0)+1
        out.append(Entity(e.entity_type,e.value,e.start,e.end,by_value[key]))
    return out


class PresidioDetector(RegexDetector):
    """Uses Presidio only when an explicitly installed spaCy model is available.

    Regex detection remains the deterministic baseline and no model is downloaded.
    """
    def __init__(self, analyzer=None, custom_patterns=None):
        super().__init__(custom_patterns)
        self.analyzer = analyzer
        self.mode = "presidio" if analyzer is not None else "regex_fallback"
    def detect(self, text: str, language: str = "de") -> list[Entity]:
        if self.analyzer is None: return super().detect(text, language)
        try:
            results = self.analyzer.analyze(text=text, language=language)
        except Exception:
            return super().detect(text, language)
        entities = [Entity(r.entity_type, text[r.start:r.end], r.start, r.end) for r in results if r.score >= 0.5]
        # Regex handles checksum-validated German identifiers and custom entities.
        entities.extend(super().detect(text, language))
        out=[]
        for e in sorted(entities, key=lambda x: (-(x.end-x.start), x.start)):
            if not any(e.start < x.end and x.start < e.end for x in out): out.append(e)
        return sorted(out, key=lambda x: x.start)
