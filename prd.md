# PRODUCT REQUIREMENTS DOCUMENT (PRD)

# FraudShield AI

## Generative AI-Powered Automated Malware Investigation Platform for Fraudulent Android APKs

Version: 1.0

Owner: Team FraudShield AI

---

# 1. Product Vision

FraudShield AI is an autonomous malware investigation platform designed to help banks, financial institutions, fraud teams, and cybersecurity analysts rapidly identify, understand, and mitigate threats posed by malicious Android APK applications.

The platform combines:

* Static Analysis
* Dynamic Analysis
* Generative AI
* Malware Classification
* Threat Intelligence
* MITRE ATT&CK Mapping
* Fraud Impact Analysis
* Risk Scoring
* Interactive AI Investigation

into a single end-to-end workflow.

---

# 2. Problem Statement

Fraudulent APKs are increasingly distributed through:

* WhatsApp
* SMS
* Telegram
* Email
* Phishing Websites

These applications impersonate legitimate organizations and are used to:

* Steal OTPs
* Capture credentials
* Exfiltrate sensitive information
* Take over customer accounts
* Perform unauthorized financial transactions

Manual malware analysis requires highly skilled analysts and significant time.

Banks require an intelligent system capable of automatically investigating suspicious APKs and generating actionable threat intelligence.

---

# 3. Goals

Primary Goals:

1. Automated APK Investigation
2. AI-Powered Malware Understanding
3. Fraud Risk Assessment
4. Faster Incident Response
5. Reduced Analyst Workload

Success Metric:

APK Investigation Time

Current:
2–8 Hours

Target:
< 2 Minutes

---

# 4. User Personas

## Security Analyst

Needs:

* Malware explanation
* Technical findings
* Risk score

---

## Fraud Team

Needs:

* Banking impact
* OTP theft detection
* Fraud indicators

---

## SOC Team

Needs:

* IOC extraction
* Threat intelligence
* MITRE mapping

---

## Management

Needs:

* Executive summaries
* Severity score
* Recommended actions

---

# 5. End-to-End Workflow

APK Upload

↓

Reverse Engineering Engine

↓

Static Analysis Engine

↓

Dynamic Analysis Sandbox

↓

Behavior Correlation Engine

↓

Threat Intelligence Engine

↓

AI Malware Analyst

↓

MITRE Mapping

↓

Fraud Impact Assessment

↓

Risk Scoring Engine

↓

Investigation Report

↓

Security Copilot Chat

---

# 6. Core Modules

=================================================

MODULE 1
APK INGESTION ENGINE

=================================================

Features:

* APK Upload
* APK Validation
* SHA256 Hashing
* Metadata Extraction

Extract:

* Package Name
* Version
* Certificate
* Signature
* File Size

Tech:

FastAPI

Outputs:

apk_metadata.json

Priority:
Critical

---

=================================================

MODULE 2
REVERSE ENGINEERING ENGINE

=================================================

Purpose:

Extract source code without original project files.

Tools:

APKTool
JADX
Androguard

Outputs:

AndroidManifest.xml

Permissions

Activities

Services

Receivers

Providers

Assets

DEX Files

Native Libraries

Priority:
Critical

---

=================================================

MODULE 3
STATIC ANALYSIS ENGINE

=================================================

Detect:

Dangerous Permissions

Suspicious APIs

Runtime Execution

Dynamic Code Loading

WebView Abuse

Root Detection

Emulator Detection

Accessibility Abuse

Hardcoded URLs

Hardcoded IPs

Secrets

Certificates

Obfuscation

Banking Impersonation

Implementation:

Python Rule Engine

Androguard

YARA Rules

Outputs:

findings.json

Priority:
Critical

---

=================================================

MODULE 4
AI REVERSE ENGINEERING

=================================================

Purpose:

Convert Decompiled Code Into Human Language

Input:

Java Source

Manifest

API Calls

Permissions

Gemini Tasks:

Explain Functionality

Explain Threat

Explain Intent

Explain Banking Impact

Output Example:

"This module intercepts SMS messages and extracts OTPs before forwarding them to a remote command server."

Priority:
Critical

---

=================================================

MODULE 5
DYNAMIC ANALYSIS SANDBOX

=================================================

Purpose:

Observe Real Behavior

Environment:

Android Emulator

Containerized Sandbox

MobSF

Frida

Captured Data:

Network Requests

DNS Queries

File Creation

File Deletion

SMS Activity

Clipboard Access

Accessibility Events

Screen Overlays

Background Services

Implementation:

Automated APK Installation

Automated Execution

Automated Monitoring

Priority:
Critical

---

=================================================

MODULE 6
MALWARE CLASSIFICATION ENGINE

=================================================

Categories:

Banking Trojan

Spyware

RAT

Dropper

Adware

Ransomware

Credential Stealer

Hybrid Threat

Input:

Static Findings

Dynamic Findings

AI Summaries

Output:

Class

Confidence

Evidence

Implementation:

Gradient Boosting / XGBoost

or Gemini Classification Layer

Priority:
High

---

=================================================

MODULE 7
THREAT INTELLIGENCE ENGINE

=================================================

Extract:

Domains

URLs

IPs

Emails

Hashes

APK Signatures

Generate:

IOC Feed

Implementation:

Regex

Threat Database

VirusTotal Integration (Optional)

Priority:
High

---

=================================================

MODULE 8
MITRE ATT&CK MAPPING

=================================================

Map Behaviors:

Credential Theft

SMS Theft

C2 Communication

Data Exfiltration

Accessibility Abuse

Persistence

Execution

Defense Evasion

Output:

Technique

Technique ID

Evidence

Priority:
High

---

=================================================

MODULE 9
BANKING FRAUD IMPACT ENGINE

=================================================

Unique Differentiator

Questions Answered:

Can steal OTP?

Can capture credentials?

Can bypass MFA?

Can overlay banking apps?

Can perform transactions?

Can impersonate bank?

Output:

Fraud Risk Narrative

Business Impact

Affected Assets

Priority:
Critical

---

=================================================

MODULE 10
RISK SCORING ENGINE

=================================================

Weighted Scoring

Example:

READ_SMS
+15

SEND_SMS
+20

Accessibility Abuse
+30

Overlay Attack
+30

C2 Communication
+25

Credential Theft
+30

Formula:

Static Score

Dynamic Score

Fraud Score

AI Confidence

Final Score

Range:

0–100

Categories:

Safe

Suspicious

High Risk

Critical

Priority:
Critical

---

=================================================

MODULE 11
AI INVESTIGATION REPORT

=================================================

Generated Automatically

Sections:

Executive Summary

Technical Findings

Behavioral Findings

Malware Classification

MITRE Mapping

Fraud Impact

Risk Score

Recommendations

Output:

PDF

HTML

JSON

Priority:
Critical

---

=================================================

MODULE 12
SECURITY COPILOT CHATBOT

=================================================

RAG Architecture

Store:

Reports

Findings

Logs

Code Analysis

User Questions:

Why is this malicious?

Can it steal OTPs?

Show suspicious domains.

Explain risk score.

Technology:

Gemini

ChromaDB

LangChain

Priority:
Medium

---

=================================================

MODULE 13
THREAT GRAPH VISUALIZER

=================================================

Generate:

Attack Chain Graph

APK

↓

Permission Abuse

↓

OTP Theft

↓

C2 Server

↓

Credential Exfiltration

↓

Fraud

Technology:

NetworkX

Mermaid

Priority:
Medium

---

# 7. Database Architecture

PostgreSQL

Tables:

apks

static_findings

dynamic_findings

ioc

mitre_mapping

risk_scores

reports

chat_sessions

---

# 8. Vector Database

ChromaDB

Stores:

Code Embeddings

Reports

Threat Intelligence

Analysis Results

Purpose:

Chatbot Retrieval

---

# 9. System Architecture

Frontend (Streamlit)

↓

FastAPI

↓

Analysis Orchestrator

↓

Static Engine

↓

Dynamic Sandbox

↓

AI Analyst

↓

Risk Engine

↓

Report Generator

↓

Database

---

# 10. Hackathon MVP

Must Build

APK Upload

Static Analysis

Gemini Reverse Engineering

MITRE Mapping

Fraud Analysis

Risk Score

PDF Report

Security Chat

Expected Completion:
48 Hours

---

# 11. Future Roadmap

Multi-APK Batch Analysis

Zero-Day Detection

Federated Threat Intelligence

APK Similarity Search

Malware Family Clustering

SOC Dashboard

SIEM Integration

Autonomous Threat Hunting

Threat Feed Sharing

Enterprise Deployment

---

# 12. Competitive Advantages

1. GenAI Malware Analyst

2. Banking Fraud Focus

3. Automated Risk Scoring

4. MITRE ATT&CK Correlation

5. Security Copilot

6. Threat Graph Visualization

7. Dynamic Analysis

8. Executive Investigation Reports

9. IOC Intelligence Extraction

10. End-to-End Automated Investigation

Result:

Transforms APK analysis from a technical scanning tool into an autonomous fraud investigation platform suitable for banking cybersecurity operations.
