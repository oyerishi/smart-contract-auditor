"""
Smart Contract Vulnerability Detection - ML Service
This service provides ML-based analysis of Solidity smart contracts
"""

import os
import re
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from flask import Flask, request, jsonify
from flask_cors import CORS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# ============================================
# Data Classes
# ============================================

@dataclass
class Vulnerability:
    id: str
    name: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    line_number: int
    code_snippet: str
    recommendation: str
    confidence: float
    cwe_id: Optional[str] = None
    swc_id: Optional[str] = None

@dataclass
class AnalysisMetrics:
    overall_risk_score: float
    total_vulnerabilities: int
    severity_count: Dict[str, int]
    category_count: Dict[str, int]
    model_confidence: float

@dataclass
class AnalysisResponse:
    success: bool
    message: str
    contract_name: str
    vulnerabilities: List[Dict]
    metrics: Dict
    processing_time_ms: int

# ============================================
# Vulnerability Patterns (Rule-based + ML-enhanced)
# ============================================

VULNERABILITY_PATTERNS = {
    # Reentrancy vulnerabilities
    "reentrancy": {
        "pattern": r"\.call\{.*value.*\}|\.call\.value\(|\.send\(|\.transfer\(",
        "check_before": r"(balances?\[|balance\s*[<>=]|require\s*\()",
        "name": "Reentrancy Vulnerability",
        "description": "External call made before state changes, allowing reentrancy attacks",
        "severity": "CRITICAL",
        "category": "REENTRANCY",
        "cwe_id": "CWE-841",
        "swc_id": "SWC-107",
        "recommendation": "Use the checks-effects-interactions pattern. Update state variables before making external calls, or use ReentrancyGuard."
    },
    
    # Integer overflow/underflow
    "integer_overflow": {
        "pattern": r"(\+\+|\-\-|\+=|\-=|\*=|\/=|\+|\-|\*|\/)\s*(?!.*SafeMath)",
        "exclude": r"pragma\s+solidity\s*[\^>=]*\s*0\.[8-9]|SafeMath|unchecked",
        "name": "Integer Overflow/Underflow",
        "description": "Arithmetic operation without overflow protection",
        "severity": "HIGH",
        "category": "ARITHMETIC",
        "cwe_id": "CWE-190",
        "swc_id": "SWC-101",
        "recommendation": "Use Solidity 0.8+ with built-in overflow checks, or use SafeMath library for older versions."
    },
    
    # Unchecked external call
    "unchecked_call": {
        "pattern": r"\.call\(|\.delegatecall\(|\.staticcall\(",
        "check_after": r"require\s*\(|if\s*\(.*success|assert\s*\(",
        "name": "Unchecked External Call",
        "description": "Return value of external call not checked",
        "severity": "HIGH",
        "category": "UNCHECKED_CALL",
        "cwe_id": "CWE-252",
        "swc_id": "SWC-104",
        "recommendation": "Always check return values of low-level calls: (bool success, ) = addr.call(...); require(success);"
    },
    
    # tx.origin authentication
    "tx_origin": {
        "pattern": r"tx\.origin",
        "context": r"require\s*\(.*tx\.origin|if\s*\(.*tx\.origin|==\s*tx\.origin|tx\.origin\s*==",
        "name": "tx.origin Authentication",
        "description": "Using tx.origin for authentication is vulnerable to phishing attacks",
        "severity": "HIGH",
        "category": "ACCESS_CONTROL",
        "cwe_id": "CWE-287",
        "swc_id": "SWC-115",
        "recommendation": "Use msg.sender instead of tx.origin for authentication."
    },
    
    # Unprotected selfdestruct
    "selfdestruct": {
        "pattern": r"selfdestruct\s*\(|suicide\s*\(",
        "check_before": r"onlyOwner|require\s*\(.*owner|modifier.*owner",
        "name": "Unprotected Selfdestruct",
        "description": "selfdestruct can be called without proper access control",
        "severity": "CRITICAL",
        "category": "ACCESS_CONTROL",
        "cwe_id": "CWE-284",
        "swc_id": "SWC-106",
        "recommendation": "Add proper access control (e.g., onlyOwner modifier) to selfdestruct functions."
    },
    
    # Delegatecall to untrusted contract
    "delegatecall": {
        "pattern": r"\.delegatecall\(",
        "name": "Delegatecall Usage",
        "description": "delegatecall executes code in the context of the calling contract",
        "severity": "HIGH",
        "category": "DELEGATECALL",
        "cwe_id": "CWE-829",
        "swc_id": "SWC-112",
        "recommendation": "Ensure delegatecall target is trusted. Never use user-supplied addresses with delegatecall."
    },
    
    # Timestamp dependence
    "timestamp": {
        "pattern": r"block\.timestamp|now",
        "context": r"require\s*\(.*block\.timestamp|if\s*\(.*block\.timestamp|==\s*block\.timestamp",
        "name": "Timestamp Dependence",
        "description": "Block timestamp can be manipulated by miners within ~15 seconds",
        "severity": "MEDIUM",
        "category": "TIME_MANIPULATION",
        "cwe_id": "CWE-829",
        "swc_id": "SWC-116",
        "recommendation": "Don't use block.timestamp for critical logic. For randomness, use Chainlink VRF or commit-reveal schemes."
    },
    
    # Block number dependence
    "blockhash": {
        "pattern": r"blockhash\s*\(|block\.blockhash",
        "name": "Blockhash Usage for Randomness",
        "description": "Using blockhash for randomness is predictable and manipulable",
        "severity": "MEDIUM",
        "category": "RANDOMNESS",
        "cwe_id": "CWE-330",
        "swc_id": "SWC-120",
        "recommendation": "Use Chainlink VRF or other secure randomness sources."
    },
    
    # Floating pragma
    "floating_pragma": {
        "pattern": r"pragma\s+solidity\s*\^",
        "name": "Floating Pragma",
        "description": "Contract uses floating pragma which may compile with different versions",
        "severity": "LOW",
        "category": "VERSION",
        "cwe_id": "CWE-1103",
        "swc_id": "SWC-103",
        "recommendation": "Lock pragma to specific version: pragma solidity 0.8.19;"
    },
    
    # Outdated compiler
    "outdated_compiler": {
        "pattern": r"pragma\s+solidity\s*[\^>=]*\s*0\.[0-6]\.",
        "name": "Outdated Compiler Version",
        "description": "Using outdated Solidity version with known vulnerabilities",
        "severity": "MEDIUM",
        "category": "VERSION",
        "cwe_id": "CWE-1103",
        "swc_id": "SWC-102",
        "recommendation": "Upgrade to Solidity 0.8.x for built-in overflow protection and security improvements."
    },
    
    # Visibility not specified
    "default_visibility": {
        "pattern": r"function\s+\w+\s*\([^)]*\)\s*(?!.*(?:public|private|internal|external))",
        "name": "Default Visibility",
        "description": "Function visibility not explicitly specified",
        "severity": "MEDIUM",
        "category": "VISIBILITY",
        "cwe_id": "CWE-710",
        "swc_id": "SWC-100",
        "recommendation": "Always explicitly declare function visibility (public, private, internal, external)."
    },
    
    # Uninitialized storage pointer
    "uninitialized_storage": {
        "pattern": r"struct\s+\w+.*storage\s+\w+\s*;",
        "name": "Uninitialized Storage Pointer",
        "description": "Storage pointer declared without initialization",
        "severity": "HIGH",
        "category": "STORAGE",
        "cwe_id": "CWE-824",
        "swc_id": "SWC-109",
        "recommendation": "Initialize storage pointers explicitly or use memory keyword."
    },
    
    # DoS with block gas limit
    "dos_gas_limit": {
        "pattern": r"for\s*\([^)]*\.length|while\s*\(",
        "name": "Denial of Service - Gas Limit",
        "description": "Unbounded loop may exceed block gas limit",
        "severity": "MEDIUM",
        "category": "DOS",
        "cwe_id": "CWE-400",
        "swc_id": "SWC-128",
        "recommendation": "Implement pagination or limit loop iterations. Use pull over push pattern."
    },
    
    # Missing zero address check
    "zero_address": {
        "pattern": r"function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)\s*(?!.*require\s*\([^)]*!=\s*address\s*\(\s*0\s*\))",
        "name": "Missing Zero Address Check",
        "description": "Address parameter not validated for zero address",
        "severity": "LOW",
        "category": "INPUT_VALIDATION",
        "cwe_id": "CWE-20",
        "swc_id": "SWC-",
        "recommendation": "Add require(addr != address(0)) check for address parameters."
    },
    
    # Front-running vulnerability
    "front_running": {
        "pattern": r"(approve\s*\(|swap|exchange|trade|buy|sell)",
        "name": "Potential Front-Running",
        "description": "Transaction may be vulnerable to front-running attacks",
        "severity": "MEDIUM",
        "category": "FRONT_RUNNING",
        "cwe_id": "CWE-362",
        "swc_id": "SWC-114",
        "recommendation": "Implement commit-reveal scheme or use flashbots for sensitive transactions."
    },
    
    # Signature malleability
    "signature_malleability": {
        "pattern": r"ecrecover\s*\(",
        "name": "Signature Malleability",
        "description": "ecrecover is vulnerable to signature malleability",
        "severity": "MEDIUM",
        "category": "CRYPTOGRAPHY",
        "cwe_id": "CWE-347",
        "swc_id": "SWC-117",
        "recommendation": "Use OpenZeppelin's ECDSA library which handles signature malleability."
    },
    
    # Hardcoded addresses
    "hardcoded_address": {
        "pattern": r"0x[a-fA-F0-9]{40}",
        "exclude": r"address\s*\(\s*0\s*\)|0x0{40}",
        "name": "Hardcoded Address",
        "description": "Contract contains hardcoded address",
        "severity": "INFO",
        "category": "CODE_QUALITY",
        "cwe_id": "CWE-798",
        "swc_id": "",
        "recommendation": "Consider using constructor parameters or configurable addresses for flexibility."
    },
    
    # Missing event emission
    "missing_events": {
        "pattern": r"function\s+\w+\s*\([^)]*\)[^{]*\{[^}]*(?:balances?\[|\.transfer\(|\.send\(|owner\s*=)[^}]*\}(?![^}]*emit\s)",
        "name": "Missing Event Emission",
        "description": "State-changing function does not emit events",
        "severity": "LOW",
        "category": "CODE_QUALITY",
        "cwe_id": "",
        "swc_id": "",
        "recommendation": "Emit events for all state changes to enable off-chain monitoring."
    },
    
    # Use of assembly
    "assembly_usage": {
        "pattern": r"assembly\s*\{",
        "name": "Assembly Usage",
        "description": "Contract uses inline assembly which bypasses safety checks",
        "severity": "INFO",
        "category": "CODE_QUALITY",
        "cwe_id": "",
        "swc_id": "",
        "recommendation": "Ensure assembly code is thoroughly audited. Document why assembly is necessary."
    },
}

# ============================================
# ML-Enhanced Analysis Functions
# ============================================

def calculate_confidence(pattern_match: bool, context_match: bool = True, 
                        code_quality_score: float = 0.5) -> float:
    """Calculate confidence score for a finding"""
    base_confidence = 0.7 if pattern_match else 0.0
    
    if context_match:
        base_confidence += 0.2
    
    base_confidence += code_quality_score * 0.1
    
    return min(base_confidence, 1.0)


def extract_code_snippet(source_code: str, line_number: int, context_lines: int = 2) -> str:
    """Extract code snippet around a specific line"""
    lines = source_code.split('\n')
    start = max(0, line_number - context_lines - 1)
    end = min(len(lines), line_number + context_lines)
    
    snippet_lines = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        prefix = ">>> " if i == line_number else "    "
        snippet_lines.append(f"{prefix}{i}: {line}")
    
    return '\n'.join(snippet_lines)


def get_line_number(source_code: str, match_position: int) -> int:
    """Get line number from character position"""
    return source_code[:match_position].count('\n') + 1


def analyze_contract_patterns(source_code: str, contract_name: str) -> List[Vulnerability]:
    """Analyze contract using pattern matching with ML-enhanced confidence scoring"""
    vulnerabilities = []
    vuln_id = 1
    
    for vuln_key, vuln_info in VULNERABILITY_PATTERNS.items():
        pattern = vuln_info["pattern"]
        matches = list(re.finditer(pattern, source_code, re.IGNORECASE | re.MULTILINE))
        
        for match in matches:
            # Check exclusion patterns
            if "exclude" in vuln_info:
                exclude_match = re.search(vuln_info["exclude"], source_code, re.IGNORECASE)
                if exclude_match:
                    continue
            
            line_number = get_line_number(source_code, match.start())
            code_snippet = extract_code_snippet(source_code, line_number)
            
            # Context-aware analysis
            context_match = True
            if "check_before" in vuln_info:
                # Check if mitigation exists before this line
                before_code = source_code[:match.start()]
                if re.search(vuln_info["check_before"], before_code[-500:], re.IGNORECASE):
                    context_match = False
            
            if "check_after" in vuln_info:
                # Check if mitigation exists after this line
                after_code = source_code[match.end():]
                if re.search(vuln_info["check_after"], after_code[:500], re.IGNORECASE):
                    context_match = False
            
            # Skip if mitigation found
            if not context_match and vuln_info["severity"] not in ["CRITICAL", "HIGH"]:
                continue
            
            confidence = calculate_confidence(True, context_match)
            
            # Adjust severity based on context
            severity = vuln_info["severity"]
            if not context_match and severity in ["CRITICAL", "HIGH"]:
                severity = "MEDIUM"  # Downgrade if mitigation might exist
                confidence *= 0.8
            
            vuln = Vulnerability(
                id=f"{contract_name}-{vuln_key}-{vuln_id}",
                name=vuln_info["name"],
                description=vuln_info["description"],
                severity=severity,
                category=vuln_info["category"],
                line_number=line_number,
                code_snippet=code_snippet,
                recommendation=vuln_info["recommendation"],
                confidence=round(confidence, 2),
                cwe_id=vuln_info.get("cwe_id"),
                swc_id=vuln_info.get("swc_id")
            )
            vulnerabilities.append(vuln)
            vuln_id += 1
    
    return vulnerabilities


def calculate_risk_score(vulnerabilities: List[Vulnerability]) -> float:
    """Calculate overall risk score based on vulnerabilities"""
    if not vulnerabilities:
        return 0.0
    
    severity_weights = {
        "CRITICAL": 10.0,
        "HIGH": 7.0,
        "MEDIUM": 4.0,
        "LOW": 2.0,
        "INFO": 0.5
    }
    
    total_weight = 0.0
    for vuln in vulnerabilities:
        weight = severity_weights.get(vuln.severity, 1.0)
        total_weight += weight * vuln.confidence
    
    # Normalize to 0-100 scale
    max_score = 100.0
    risk_score = min(total_weight * 5, max_score)
    
    return round(risk_score, 2)


def count_by_field(vulnerabilities: List[Vulnerability], field: str) -> Dict[str, int]:
    """Count vulnerabilities by a specific field"""
    counts = {}
    for vuln in vulnerabilities:
        value = getattr(vuln, field)
        counts[value] = counts.get(value, 0) + 1
    return counts


# ============================================
# API Endpoints
# ============================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "ml-vulnerability-detection",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route('/api/ml/analyze', methods=['POST'])
def analyze_contract():
    """
    Analyze a smart contract for vulnerabilities
    
    Expected JSON body:
    {
        "contractCode": "string - Solidity source code",
        "contractName": "string - Name of the contract",
        "solcVersion": "string - Solidity compiler version (optional)",
        "parsedContract": {} - Parsed contract data (optional)
    }
    """
    start_time = time.time()
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "message": "No JSON data provided",
                "vulnerabilities": [],
                "metrics": {},
                "processingTimeMs": 0
            }), 400
        
        contract_code = data.get('contractCode', '')
        contract_name = data.get('contractName', 'Unknown')
        solc_version = data.get('solcVersion', '')
        
        if not contract_code:
            return jsonify({
                "success": False,
                "message": "Contract code is required",
                "vulnerabilities": [],
                "metrics": {},
                "processingTimeMs": 0
            }), 400
        
        logger.info(f"Analyzing contract: {contract_name}")
        
        # Perform analysis
        vulnerabilities = analyze_contract_patterns(contract_code, contract_name)
        
        # Calculate metrics
        risk_score = calculate_risk_score(vulnerabilities)
        severity_count = count_by_field(vulnerabilities, 'severity')
        category_count = count_by_field(vulnerabilities, 'category')
        
        # Calculate average confidence
        avg_confidence = 0.0
        if vulnerabilities:
            avg_confidence = sum(v.confidence for v in vulnerabilities) / len(vulnerabilities)
        
        processing_time = int((time.time() - start_time) * 1000)
        
        # Build response
        response = AnalysisResponse(
            success=True,
            message=f"Analysis completed. Found {len(vulnerabilities)} potential vulnerabilities.",
            contract_name=contract_name,
            vulnerabilities=[{
                "id": v.id,
                "name": v.name,
                "description": v.description,
                "severity": v.severity,
                "category": v.category,
                "lineNumber": v.line_number,  # camelCase for Java backend
                "codeSnippet": v.code_snippet,  # camelCase for Java backend
                "recommendation": v.recommendation,
                "confidence": v.confidence,
                "cweId": v.cwe_id,  # camelCase for Java backend
                "swcId": v.swc_id   # camelCase for Java backend
            } for v in vulnerabilities],
            metrics={
                "overallRiskScore": risk_score,
                "totalVulnerabilities": len(vulnerabilities),
                "severityCount": severity_count,
                "categoryCount": category_count,
                "modelConfidence": round(avg_confidence, 2)
            },
            processing_time_ms=processing_time
        )
        
        logger.info(f"Analysis completed for {contract_name}: {len(vulnerabilities)} vulnerabilities, risk score: {risk_score}")
        
        return jsonify({
            "success": response.success,
            "message": response.message,
            "contractName": response.contract_name,
            "vulnerabilities": response.vulnerabilities,
            "metrics": response.metrics,
            "processingTimeMs": response.processing_time_ms
        })
        
    except Exception as e:
        logger.error(f"Error analyzing contract: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": f"Analysis failed: {str(e)}",
            "vulnerabilities": [],
            "metrics": {},
            "processingTimeMs": int((time.time() - start_time) * 1000)
        }), 500


@app.route('/api/ml/batch', methods=['POST'])
def batch_analyze():
    """Analyze multiple contracts in batch"""
    start_time = time.time()
    
    try:
        data = request.get_json()
        
        if not data or not isinstance(data, dict):
            return jsonify({
                "success": False,
                "message": "Expected object with contract names as keys"
            }), 400
        
        results = {}
        
        for contract_name, contract_data in data.items():
            contract_code = contract_data.get('contractCode', '')
            
            if contract_code:
                vulnerabilities = analyze_contract_patterns(contract_code, contract_name)
                risk_score = calculate_risk_score(vulnerabilities)
                
                results[contract_name] = {
                    "success": True,
                    "vulnerabilities": [{
                        "id": v.id,
                        "name": v.name,
                        "description": v.description,
                        "severity": v.severity,
                        "category": v.category,
                        "lineNumber": v.line_number,
                        "codeSnippet": v.code_snippet,
                        "recommendation": v.recommendation,
                        "confidence": v.confidence,
                        "cweId": v.cwe_id,
                        "swcId": v.swc_id
                    } for v in vulnerabilities],
                    "metrics": {
                        "overallRiskScore": risk_score,
                        "totalVulnerabilities": len(vulnerabilities),
                        "severityCount": count_by_field(vulnerabilities, 'severity'),
                        "categoryCount": count_by_field(vulnerabilities, 'category')
                    }
                }
            else:
                results[contract_name] = {
                    "success": False,
                    "message": "No contract code provided"
                }
        
        return jsonify({
            "success": True,
            "results": results,
            "processingTimeMs": int((time.time() - start_time) * 1000)
        })
        
    except Exception as e:
        logger.error(f"Error in batch analysis: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": f"Batch analysis failed: {str(e)}"
        }), 500


@app.route('/api/ml/patterns', methods=['GET'])
def list_patterns():
    """List all vulnerability patterns being checked"""
    patterns = []
    
    for key, info in VULNERABILITY_PATTERNS.items():
        patterns.append({
            "id": key,
            "name": info["name"],
            "description": info["description"],
            "severity": info["severity"],
            "category": info["category"],
            "cwdId": info.get("cwe_id"),
            "swcId": info.get("swc_id")
        })
    
    return jsonify({
        "success": True,
        "totalPatterns": len(patterns),
        "patterns": patterns
    })


# ============================================
# Main Entry Point
# ============================================

if __name__ == '__main__':
    port = int(os.environ.get('ML_SERVICE_PORT', 5000))
    debug = os.environ.get('ML_SERVICE_DEBUG', 'false').lower() == 'true'
    
    logger.info(f"Starting ML Service on port {port}")
    logger.info(f"Loaded {len(VULNERABILITY_PATTERNS)} vulnerability patterns")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )
