"""Config settings, entity lists, and thresholds."""

import os

# Deterministic seed for fake values
RANDOM_SEED = 42

# DOCX file paths
INPUT_DOCX = os.path.join(os.path.dirname(__file__), "..", "Red Herring Prospectus.docx")
OUTPUT_DOCX = os.path.join(os.path.dirname(__file__), "..", "redacted_prospectus.docx")

# Category constants
CAT_EMAIL        = "EMAIL"
CAT_PHONE        = "PHONE"
CAT_IP           = "IP_ADDRESS"
CAT_CC           = "CREDIT_CARD"
CAT_SSN          = "SSN"
CAT_DOB          = "DATE_OF_BIRTH"
CAT_ADDRESS      = "ADDRESS"
CAT_PERSON       = "PERSON_NAME"
CAT_COMPANY      = "COMPANY_NAME"
CAT_CIN          = "CIN"
CAT_PAN          = "PAN"
CAT_DIN          = "DIN"
CAT_PINCODE      = "PINCODE"


# Known PII entities from the prospectus
KNOWN_PERSONS = [
    # Issuer contact
    "Sarthak Malvadkar",
    # Promoters
    "Kushal Subbayya Hegde",
    "Pushpa Kushal Hegde",
    "Rajesh Kushal Hegde",
    "Rohit Kushal Hegde",
    "Rakhi Girija Shetty",
    # Nuvama (Lead Manager)
    "Lokesh Shah",
    "Soumavo Sarkar",
    # ICICI Securities
    "Kishan Rastogi",
    "Abhijit Diwan",
    # HDFC Bank
    "Pravin Teli",
    "Siddharth Jadhav",
    "Hitesh Ramani",
    "Manisha Shukla",
    "Sachin Gawade",
    "Tushar Gavankar",
    "Eric Bacha",
    # IndusInd Bank
    "Sharmila Joshi",
    # ICICI Bank
    "Cherag Gyara",
    # Bajaj Finserv
    "Anand Soni",
    # Nuvama additional
    "Prakash Boricha",
    "Sheetal Parab",
    "Tushar Wakhele",
    # Federal Bank
    "Ashish Mathew Pulloor",
    # SBI
    "Shanti Gopalkrishnan",
    # Registrar contact
    "Chitra Raste",
    "Varun Badai",
    # Additional from document
    "Parag Pansare",
]

KNOWN_COMPANIES = [
    # Issuer
    "KSH International Limited",
    "KSH International",
    # Lead managers and banks
    "Nuvama Wealth Management Limited",
    "HDFC Bank Limited",
    "ICICI Bank Limited",
    "ICICI Securities Limited",
    "Bajaj Finance Limited",
    "Federal Bank",
    "IndusInd Bank Limited",
    "Exim Bank",
    "State Bank of India",
    "Mufg Bank",
    # Legal and professional
    "Kirtane & Pandit LLP",
    "Trilegal",
    # Promoter family trusts
    "Dhaulagiri Family Trust",
    "Everest Family Trust",
    "Makalu Family Trust",
    "Broad Family Trust",
    "Annapurna Family Trust",
    "Kanchenjunga Family Trust",
    "Family Trust",
    "Escrow Collection Bank",
    # Promoter companies
    "Waterloo Industrial Park VI Private Limited",
    "Waterloo Industrial Park",
    # Subsidiaries / group companies
    "KSH Extrusion Private Limited",
    "KSH Extrusion",
    "KSH Distriparks Private Limited",
    "KSH Distriparks",
    # Other firms mentioned
    "Link Intime India Private Limited",
    "Link Intime India",
    "Bombay Stock Exchange",
    "National Stock Exchange",
    "Securities and Exchange Board of India",
]

# Confidence thresholds
CONFIDENCE_HIGH   = 0.90
CONFIDENCE_MEDIUM = 0.70
CONFIDENCE_LOW    = 0.50

# Minimum confidence required to redact
REDACT_THRESHOLD  = 0.70
