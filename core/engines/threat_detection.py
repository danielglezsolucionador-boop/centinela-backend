import re
import math
from datetime import datetime
from typing import Optional
from core.memory.threat_memory import ThreatMemory

# Patrones de amenazas conocidas
INJECTION_PATTERNS = [
    r"ignora\s+(las\s+)?instrucciones\s+(anteriores|previas|del\s+sistema)",
    r"ignore\s+(previous|prior|all|system)\s+instructions",
    r"olvida\s+(todo|las\s+instrucciones)",
    r"forget\s+(everything|all\s+instructions|your\s+instructions)",
    r"new\s+instructions?\s*:",
    r"nuevas\s+instrucciones?\s*:",
    r"system\s*prompt\s*:",
    r"\[system\]",
    r"<system>",
    r"###\s*instruction",
]

JAILBREAK_PATTERNS = [
    r"\bDAN\b",
    r"do\s+anything\s+now",
    r"jailbreak",
    r"sin\s+restricciones\s+(éticas|morales|de\s+seguridad)",
    r"without\s+(ethical|moral|safety)\s+restrictions",
    r"actúa\s+como\s+si\s+(fueras|no\s+tuvieras)",
    r"act\s+as\s+if\s+you\s+(were|had\s+no)",
    r"pretend\s+you\s+(are|have\s+no)",
    r"imagina\s+que\s+eres\s+una\s+ia\s+sin",
    r"modo\s+developer",
    r"developer\s+mode",
    r"unrestricted\s+mode",
]

DATA_EXFIL_PATTERNS = [
    r"(envía|manda|send|forward)\s+.{0,50}(pastebin|hastebin|webhook|discord\.com/api)",
    r"(muestra|reveal|show|display)\s+.{0,30}(api\s*key|token|secret|password|contraseña)",
    r"(extrae|extract|dump)\s+.{0,30}(base\s+de\s+datos|database|credentials)",
    r"curl\s+.{0,100}(pastebin|webhook|external)",
    r"(http|https)://(?!anthropic|openai|claude)",
]

EXTRACTION_PATTERNS = [
    r"(muestra|reveal|display|show|dime|tell\s+me)\s+.{0,40}(system\s+prompt|instrucciones\s+del\s+sistema|prompt\s+completo)",
    r"what\s+(are\s+your|is\s+your)\s+(instructions?|system\s+prompt|prompt)",
    r"(repite|repeat)\s+.{0,30}(instrucciones|instructions|prompt)",
    r"(cuáles|what)\s+(son\s+tus|are\s+your)\s+(instrucciones|instructions|reglas|rules)",
]

ROLE_MANIPULATION_PATTERNS = [
    r"(eres|you\s+are)\s+(ahora|now)\s+(un|a|an)\s+\w+\s+(sin|without)\s+(restricciones|restrictions)",
    r"(tu\s+nuevo\s+rol|your\s+new\s+role)\s+(es|is)",
    r"(olvida|forget)\s+(que\s+eres|you\s+are)\s+(claude|gpt|an\s+ai|una\s+ia)",
    r"(desde\s+ahora|from\s+now\s+on)\s+(eres|you\s+are|act\s+as)",
]

THREAT_PATTERNS = {
    "PROMPT_INJECTION": INJECTION_PATTERNS,
    "JAILBREAK": JAILBREAK_PATTERNS,
    "DATA_EXFILTRATION": DATA_EXFIL_PATTERNS,
    "SYSTEM_EXTRACTION": EXTRACTION_PATTERNS,
    "ROLE_MANIPULATION": ROLE_MANIPULATION_PATTERNS,
}

THREAT_WEIGHTS = {
    "PROMPT_INJECTION": 0.35,
    "JAILBREAK": 0.30,
    "DATA_EXFILTRATION": 0.25,
    "SYSTEM_EXTRACTION": 0.20,
    "ROLE_MANIPULATION": 0.15,
}

SUSPICIOUS_KEYWORDS = [
    "bypass", "override", "unlimited", "unrestricted", "jailbreak",
    "hack", "exploit", "vulnerability", "injection", "payload",
    "sin límites", "sin restricciones", "modo dios", "god mode",
    "root access", "admin mode", "sudo", "superuser",
]

class ThreatDetectionEngine:
    def __init__(self, threat_memory: Optional[ThreatMemory] = None):
        self.threat_memory = threat_memory
        self.compiled_patterns = {}
        self._compile_patterns()
        self.detection_stats = {
            "total_analyzed": 0,
            "threats_detected": 0,
            "by_type": {k: 0 for k in THREAT_PATTERNS.keys()},
        }

    def _compile_patterns(self):
        for threat_type, patterns in THREAT_PATTERNS.items():
            self.compiled_patterns[threat_type] = [
                re.compile(p, re.IGNORECASE | re.UNICODE)
                for p in patterns
            ]

    def analyze(self, content: str, context: dict = None) -> dict:
        if not content:
            return self._clean_result()

        self.detection_stats["total_analyzed"] += 1
        content_lower = content.lower()
        detected_threats = []
        threat_scores = {}
        matched_patterns = []

        # Análisis de patrones
        for threat_type, patterns in self.compiled_patterns.items():
            matches = []
            for pattern in patterns:
                match = pattern.search(content)
                if match:
                    matches.append(match.group(0)[:100])

            if matches:
                weight = THREAT_WEIGHTS[threat_type]
                confidence = min(1.0, len(matches) * 0.4 + 0.6)
                threat_scores[threat_type] = weight * confidence
                detected_threats.append(threat_type)
                matched_patterns.extend(matches)
                self.detection_stats["by_type"][threat_type] += 1

        # Análisis de keywords sospechosas
        suspicious_found = [
            kw for kw in SUSPICIOUS_KEYWORDS
            if kw.lower() in content_lower
        ]
        keyword_score = min(0.3, len(suspicious_found) * 0.06)

        # Análisis heurístico
        heuristic_score = self._heuristic_analysis(content, context or {})

        # Score final
        pattern_score = sum(threat_scores.values())
        total_score = min(100, (pattern_score * 60) + (keyword_score * 20) + (heuristic_score * 20))

        threat_detected = total_score >= 35 or len(detected_threats) > 0

        if threat_detected:
            severity = "NONE"

        return {
            "threat_detected": threat_detected,
            "threat_types": detected_threats,
            "severity": severity,
            "detection_score": round(total_score, 2),
            "confidence": round(min(1.0, total_score / 100), 2),
            "pattern_score": round(pattern_score * 60, 2),
            "keyword_score": round(keyword_score * 20, 2),
            "heuristic_score": round(heuristic_score * 20, 2),
            "matched_patterns": matched_patterns[:10],
            "suspicious_keywords": suspicious_found,
            "analysis_timestamp": datetime.utcnow().isoformat(),
        }

    def _heuristic_analysis(self, content: str, context: dict) -> float:
        score = 0.0
        
        # Longitud sospechosa
        if len(content) > 2000:
            score += 0.1
        
        # Muchos caracteres especiales
        special_chars = sum(1 for c in content if c in "[]{}()<>|\\")
        if special_chars > 10:
            score += 0.15
        
        # Cambios de idioma sospechosos
        has_spanish = bool(re.search(r'[áéíóúñ¿¡]', content))
        has_english_commands = bool(re.search(r'\b(ignore|forget|pretend|act as)\b', content, re.I))
        if has_spanish and has_english_commands:
            score += 0.2
        
        # Instrucciones anidadas
        nested_instructions = content.count("instrucciones") + content.count("instructions")
        if nested_instructions > 2:
            score += 0.15
        
        # URLs externas
        external_urls = re.findall(r'https?://\S+', content)
        if external_urls:
            score += 0.2 * min(1.0, len(external_urls) * 0.3)
        
        # Contexto de agente de alto riesgo
        high_risk_agents = ["mcf", "cerebro", "sniff_amazon", "creador_apis"]
        if context.get("agent", "").lower() in high_risk_agents:
            score += 0.1

        return min(1.0, score)

    def get_stats(self) -> dict:
        total = self.detection_stats["total_analyzed"]
        detected = self.detection_stats["threats_detected"]
        return {
            **self.detection_stats,
            "detection_rate": round(detected / total * 100, 2) if total > 0 else 0,
        }

    def _clean_result(self) -> dict:
        return {
            "threat_detected": False,
            "threat_types": [],
            "severity": "NONE",
            "detection_score": 0,
            "confidence": 0,
            "pattern_score": 0,
            "keyword_score": 0,
            "heuristic_score": 0,
            "matched_patterns": [],
            "suspicious_keywords": [],
            "analysis_timestamp": datetime.utcnow().isoformat(),
        }
