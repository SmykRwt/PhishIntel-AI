import time
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from typing import List, Optional

from backend.app.schemas.analysis import AnalysisRequest, AnalysisResponse
from backend.app.core.dependencies import get_predictor, get_llm_analyst
from backend.app.services.email_parser import EmailParser
from backend.app.services.url_analyzer import URLAnalyzer
from backend.app.services.threat_scorer import ThreatScorer
from backend.app.services.ocr_service import OCRService
from backend.app.rules.engine import RuleEngine

logger = logging.getLogger("phishing_platform")
router = APIRouter()

async def run_pipeline_and_save(
    text_content: str,
    raw_eml: Optional[str],
    is_eml: bool,
    sender: str,
    reply_to: str,
    subject: str,
    urls: List[str],
    attachments: List[dict],
    headers: dict,
    predictor,
    llm_analyst
) -> dict:
    """Helper that runs threat scoring, OCR or email text analysis, and queries the LLM."""
    t0 = time.time()

    # 1. Parse/Analyze URLs
    url_findings_list = []
    for url in urls[:5]:  # Analyze up to 5 URLs to keep it fast
        analysis_res = URLAnalyzer.analyze_url(url)
        url_findings_list.append(analysis_res)

    # 2. Compile Parsed Data for Rules Engine
    email_data = {
        "body": text_content,
        "subject": subject,
        "urls": urls,
        "attachments": attachments,
        "sender": sender,
        "reply_to": reply_to
    }
    triggered_rules = RuleEngine.evaluate_rules(email_data)

    # 3. Predict probabilities using ML models
    bert_context = f"Subject: {subject}\n\n{text_content}" if subject else text_content
    probs = predictor.predict_bert(bert_context)
    spam_prob = float(probs[1]) * 100.0  # Percentage

    # 4. Composite Risk Score
    scoring_result = ThreatScorer.compute_risk_score(
        bert_spam_prob=spam_prob,
        rules=triggered_rules,
        url_findings=url_findings_list
    )
    
    risk_score = scoring_result["risk_score"]
    verdict = scoring_result["verdict"]

    # 5. GenAI Explanation Report
    llm_report_dict = await llm_analyst.analyze_threat(
        verdict=verdict,
        risk_score=risk_score,
        rules=[r.model_dump() for r in triggered_rules],
        urls=url_findings_list,
        headers={},
        email_text=text_content
    )

    processing_time = time.time() - t0

    # 6. Return response dictionary directly (Stateless)
    return {
        "id": 1,
        "text": text_content,
        "raw_eml": raw_eml,
        "prediction_label": verdict,
        "risk_score": risk_score,
        "model_version": "DistilBERT-v1 + Classical Ensemble",
        "processing_time": processing_time,
        "created_at": datetime.now(),
        "rules_triggered": triggered_rules,
        "url_findings": url_findings_list,
        "llm_report": llm_report_dict
    }


@router.post("/email", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED)
async def analyze_email_json(
    request: AnalysisRequest,
    predictor = Depends(get_predictor),
    llm_analyst = Depends(get_llm_analyst)
):
    """Analyzes raw email/text submitted in a JSON payload."""
    parsed = EmailParser.parse_raw_text(request.text)
    
    # Run pipeline
    return await run_pipeline_and_save(
        text_content=parsed["body"],
        raw_eml=request.raw_eml,
        is_eml=parsed["is_eml"],
        sender=parsed["sender"],
        reply_to=parsed["reply_to"],
        subject=parsed["subject"],
        urls=parsed["urls"],
        attachments=parsed["attachments"],
        headers=parsed["headers"],
        predictor=predictor,
        llm_analyst=llm_analyst
    )


@router.post("/email/upload", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED)
async def analyze_email_upload(
    file: UploadFile = File(...),
    predictor = Depends(get_predictor),
    llm_analyst = Depends(get_llm_analyst)
):
    """Analyzes an uploaded .eml file."""
    content_bytes = await file.read()
    content_str = content_bytes.decode(errors="ignore")
    
    parsed = EmailParser.parse_eml(content_str)
    
    return await run_pipeline_and_save(
        text_content=parsed["body"],
        raw_eml=content_str,
        is_eml=True,
        sender=parsed["sender"],
        reply_to=parsed["reply_to"],
        subject=parsed["subject"],
        urls=parsed["urls"],
        attachments=parsed["attachments"],
        headers=parsed["headers"],
        predictor=predictor,
        llm_analyst=llm_analyst
    )


@router.post("/screenshot", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED)
async def analyze_screenshot(
    file: UploadFile = File(...),
    predictor = Depends(get_predictor),
    llm_analyst = Depends(get_llm_analyst)
):
    """Extracts text from screenshot upload using Tesseract OCR and performs phishing analysis."""
    image_bytes = await file.read()
    extracted_text = OCRService.extract_text_from_bytes(image_bytes)
    
    if not extracted_text or extracted_text.startswith("[OCR"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to perform OCR extraction: {extracted_text}"
        )
        
    parsed = EmailParser.parse_raw_text(extracted_text)
    
    return await run_pipeline_and_save(
        text_content=parsed["body"],
        raw_eml=f"[Extracted via OCR]\n{extracted_text}",
        is_eml=False,
        sender=parsed["sender"],
        reply_to=parsed["reply_to"],
        subject=parsed["subject"],
        urls=parsed["urls"],
        attachments=[],
        headers=parsed.get("headers", {}),
        predictor=predictor,
        llm_analyst=llm_analyst
    )
