# OSINT Recon Suite

An automated Open Source Intelligence (OSINT) reconnaissance framework for digital footprinting, threat actor investigation, and security assessments.

## What It Does

- **Username Enumeration**: Discover accounts across social media, forums, and platforms
- **Email Intelligence**: Verify email validity, check for breaches, find associated accounts
- **Domain Reconnaissance**: Harvest subdomains, emails, and hosts from target domains
- **Report Generation**: Export findings to structured JSON and PDF reports

## Tech Stack

- Python 3.x
- Sherlock (username enumeration)
- Holehe (email OSINT)
- theHarvester (domain reconnaissance)
- ReportLab (PDF generation)

## Installation

```bash
git clone https://github.com/ZeakMeadows/osint-recon-suite.git
cd osint-recon-suite
pip install -r requirements.txt
```
## Usage

```bash
# Username investigation
python osint_suite.py --target "username" --type username

# Email intelligence
python osint_suite.py --target "email@example.com" --type email

# Domain reconnaissance
python osint_suite.py --target "example.com" --type domain
```
## What I Learned

- API integration and rate limit management
- Asynchronous data aggregation from multiple sources
- Structured data normalization and reporting

## Future Improvements

- [ ] Add Shodan integration for IP/asset discovery
- [ ] Add WHOIS and DNS enumeration modules
- [ ] Create web dashboard for interactive investigations
