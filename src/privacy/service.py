from .detector import RegexDetector, assign_placeholders
from .vault import SessionVault

class PrivacyService:
    def __init__(self, detector=None, vault=None): self.detector=detector or RegexDetector(); self.vault=vault or SessionVault()
    def anonymize(self,prompt,language="de"):
        if len(prompt.encode("utf-8")) > 100*1024: raise ValueError("prompt exceeds 100 KiB")
        if language not in {"de", "en"}: raise ValueError("language must be de or en")
        entities=assign_placeholders(self.detector.detect(prompt,language)); result=prompt
        for e in sorted(entities,key=lambda x:x.start,reverse=True): result=result[:e.start]+e.placeholder+result[e.end:]
        sid=self.vault.create(entities)
        return {"anonymized_prompt":result,"session_id":sid,"pii_count":len(entities)}
    def deanonymize(self,text,session_id): return {"restored_text":self.vault.restore(session_id,text)}
    def stats(self): return self.vault.stats_snapshot(self.detector.mode,["de","en"])
