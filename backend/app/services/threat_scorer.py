from typing import List, Dict, Any
from backend.app.schemas.analysis import RuleResult

class ThreatScorer:
    @staticmethod
    def calculate_rules_score(rules: List[RuleResult]) -> float:
        """Returns a score from 0 to 100 based on triggered rules."""
        if not rules:
            return 0.0
        
        severity_mapping = {
            "critical": 95.0,
            "high": 75.0,
            "medium": 45.0,
            "low": 15.0
        }
        
        scores = []
        for rule in rules:
            sev = rule.severity.lower()
            scores.append(severity_mapping.get(sev, 10.0))
            
        max_score = max(scores)
        count_bonus = min(len(scores) - 1, 5) * 5.0  # Up to 25 points bonus for multiple triggers
        
        return min(max_score + count_bonus, 100.0)

    @staticmethod
    def calculate_urls_score(url_findings: List[Any]) -> float:
        """Returns a score from 0 to 100 based on parsed URL vulnerabilities."""
        if not url_findings:
            return 0.0
        
        suspicious_urls = []
        for u in url_findings:
            is_susp = u.get("is_suspicious") if isinstance(u, dict) else getattr(u, "is_suspicious", False)
            if is_susp:
                suspicious_urls.append(u)

        if not suspicious_urls:
            return 0.0
            
        flag_scores = {
            "insecure http protocol": 30.0,
            "url shortener service used": 60.0,
            "suspicious tld": 65.0,
            "high domain name entropy (dga indicator)": 70.0,
            "ip-based url host": 75.0,
            "brand impersonation": 80.0,
            "idn homograph attack indicator (non-ascii characters)": 85.0,
            "typosquatting detected": 90.0,
            "unusually long url": 15.0
        }
        
        scores = []
        for u in suspicious_urls:
            flags = u.get("flags", []) if isinstance(u, dict) else getattr(u, "flags", [])
            if isinstance(flags, str):
                flags = [f.strip() for f in flags.split(",") if f.strip()]
                
            for flag in flags:
                matched = False
                for k, v in flag_scores.items():
                    if k in flag.lower():
                        scores.append(v)
                        matched = True
                if not matched:
                    scores.append(20.0)
                    
        if not scores:
            return 10.0
            
        return float(min(max(scores) + min(len(scores) - 1, 3) * 5.0, 100.0))

    @staticmethod
    def compute_risk_score(
        bert_spam_prob: float,
        rules: List[RuleResult],
        url_findings: List[Any]
    ) -> Dict[str, Any]:
        """
        Combines predictions, rules, and URLs into a composite risk score (0-100).
        Weights dynamically re-allocated if URLs are not present/applicable.
        """
        rules_score = ThreatScorer.calculate_rules_score(rules)
        urls_score = ThreatScorer.calculate_urls_score(url_findings)
        
        url_applicable = len(url_findings) > 0
        
        # Default weights
        weights = {
            "bert": 0.60,
            "rules": 0.25,
            "urls": 0.15
        }
        
        active = ["bert", "rules"]
        if url_applicable:
            active.append("urls")
            
        total_active_weight = sum(weights[c] for c in active)
        
        weighted_score = 0.0
        if total_active_weight > 0:
            norm_bert = weights["bert"] / total_active_weight
            norm_rules = weights["rules"] / total_active_weight
            
            weighted_score += (bert_spam_prob * norm_bert) + (rules_score * norm_rules)
            
            if "urls" in active:
                norm_urls = weights["urls"] / total_active_weight
                weighted_score += urls_score * norm_urls
        else:
            weighted_score = (bert_spam_prob + rules_score) / 2.0
            
        risk_score = float(round(min(max(weighted_score, 0.0), 100.0), 2))
        
        # If BERT is highly confident, ensure the risk score reflects that
        if bert_spam_prob >= 85.0:
            risk_score = max(risk_score, float(round(bert_spam_prob * 0.85, 2)))
            
        # Determine classification label
        if risk_score >= 70.0:
            verdict = "⚠️ High Phishing Risk"
        elif risk_score >= 40.0:
            verdict = "🟡 Suspicious"
        else:
            verdict = "✅ Safe"
            
        return {
            "risk_score": risk_score,
            "verdict": verdict,
            "breakdown": {
                "bert_score": float(round(bert_spam_prob, 2)),
                "rules_score": float(round(rules_score, 2)),
                "urls_score": float(round(urls_score, 2))
            }
        }
