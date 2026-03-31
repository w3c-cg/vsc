# vsc-cg-folder-generator.ps1
# Simplified version - Generates folder structure for W3C Verifiable Supply Chain CG

Write-Host "Generating VSC CG Folder Structure..." -ForegroundColor Yellow

# Define all folders to create
$folders = @(
    "profiles/pharmaceuticals",
    "profiles/critical-minerals",
    "profiles/food-beverage",
    "profiles/luxury-goods",
    "profiles/electronics",
    "profiles/automotive",
    "interoperability/epcis",
    "interoperability/iso",
    "interoperability/regulatory",
    "interoperability/api-mapping",
    "trust-framework/governance",
    "trust-framework/accreditation",
    "trust-framework/templates",
    "trust-framework/liability",
    "use-cases/case-studies",
    "use-cases/calculators",
    "use-cases/guides",
    "use-cases/roi-models",
    "tools/libraries",
    "tools/python",
    "tools/typescript",
    "tools/test-suites",
    "tools/examples",
    "specs/profiles",
    "specs/api",
    "specs/json-schemas",
    ".github/workflows",
    ".github/ISSUE_TEMPLATE",
    "docs",
    "meetings",
    "assets/images"
)

# Create folders
foreach ($folder in $folders) {
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
    Write-Host "  Created: $folder" -ForegroundColor Gray
}

# Create .gitkeep files
Get-ChildItem -Directory -Recurse | ForEach-Object {
    $keepFile = Join-Path $_.FullName ".gitkeep"
    if (-not (Test-Path $keepFile)) {
        New-Item -ItemType File -Force -Path $keepFile | Out-Null
    }
}

# Create meeting template
$meetingContent = "# VSC CG Meeting - [Date]

**Chair**: 
**Scribe**: 
**Attendees**: 

## Agenda
1. 

## Minutes

## Decisions

## Action Items
- [ ] 

## Next Meeting"
$meetingContent | Out-File -FilePath "meetings/meeting-template.md" -Encoding utf8

# Create issue template - Profile Proposal
$profileProposal = "---
name: Profile Proposal
about: Propose a new industry profile
title: '[Profile] '
labels: profile-proposal
---

## Profile Name

## Industry Context

## Business Problem

## Proposed Data Model

## Regulatory Alignment"
$profileProposal | Out-File -FilePath ".github/ISSUE_TEMPLATE/profile-proposal.md" -Encoding utf8

# Create issue template - Use Case
$useCase = "---
name: Use Case
about: Document a supply chain use case
title: '[Use Case] '
labels: use-case
---

## Title

## Actors

## Flow

## Expected Benefits"
$useCase | Out-File -FilePath ".github/ISSUE_TEMPLATE/use-case.md" -Encoding utf8

# Create issue template - Interoperability Issue
$interopIssue = "---
name: Interoperability Issue
about: Report interoperability issues with standards
title: '[Interop] '
labels: interoperability
---

## Standards Involved

## Issue Description

## Expected Behavior

## Current Behavior

## Proposed Solution"
$interopIssue | Out-File -FilePath ".github/ISSUE_TEMPLATE/interoperability-issue.md" -Encoding utf8

# Create GitHub workflow - CI
$ciYml = "name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate JSON Schemas
        run: echo 'Add validation logic here'
      
  lint-markdown:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Markdown Lint
        run: echo 'Add markdown linting here'"
$ciYml | Out-File -FilePath ".github/workflows/ci.yml" -Encoding utf8

# Create GitHub workflow - Publish
$publishYml = "name: Publish

on:
  push:
    tags:
      - 'v*'

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Create Release
        run: echo 'Add release logic here'"
$publishYml | Out-File -FilePath ".github/workflows/publish.yml" -Encoding utf8

# Create specs README
$specsReadme = "# Specifications Directory

## profiles/
Industry-specific VC/UORA profiles

## api/
API specifications for interoperability

## json-schemas/
JSON Schema definitions for credentials and presentations"
$specsReadme | Out-File -FilePath "specs/README.md" -Encoding utf8

# Create tools README
$toolsReadme = "# Tools Directory

## libraries/
Core libraries for VC/UORA implementation

## python/
Python implementation and utilities

## typescript/
TypeScript/JavaScript implementation

## test-suites/
Conformance test suites

## examples/
Example implementations and demos"
$toolsReadme | Out-File -FilePath "tools/README.md" -Encoding utf8

# Create profiles README
$profilesReadme = "# Industry Profiles

## pharmaceuticals/
DSCSA-aligned verifiable credentials for pharmaceutical supply chains

## critical-minerals/
Conflict minerals traceability and ethical sourcing

## food-beverage/
Farm-to-fork provenance and food safety

## luxury-goods/
Anti-counterfeiting attestations for luxury products

## electronics/
Electronics supply chain traceability and conflict minerals

## automotive/
Automotive parts provenance and certification"
$profilesReadme | Out-File -FilePath "profiles/README.md" -Encoding utf8

# Create interoperability README
$interopReadme = "# Interoperability Directory

## epcis/
GS1 EPCIS to VC/UORA mapping specifications

## iso/
Alignment with ISO supply chain standards

## regulatory/
Regulatory compliance mappings (DSCSA, EUDR, CBAM, etc.)

## api-mapping/
API specifications for interoperability"
$interopReadme | Out-File -FilePath "interoperability/README.md" -Encoding utf8

# Create trust-framework README
$trustReadme = "# Trust Framework Directory

## governance/
Governance models for supply chain consortia

## accreditation/
Trust anchor accreditation criteria

## templates/
Reusable trust framework templates

## liability/
Liability and legal entity frameworks"
$trustReadme | Out-File -FilePath "trust-framework/README.md" -Encoding utf8

# Create use-cases README
$useCasesReadme = "# Use Cases Directory

## case-studies/
Real-world implementation case studies with ROI data

## calculators/
ROI calculators and modeling tools

## guides/
Implementation playbooks and pilot templates

## roi-models/
Quantified ROI models for different use cases"
$useCasesReadme | Out-File -FilePath "use-cases/README.md" -Encoding utf8

# Create docs README
$docsReadme = "# Documentation

## For Implementers
- Getting started guides
- API reference
- Best practices

## For Standards Developers
- Profile creation guide
- Trust framework guide

## For Business Leaders
- Executive summary
- ROI calculator"
$docsReadme | Out-File -FilePath "docs/README.md" -Encoding utf8

# Create .gitignore
$gitignore = "# Dependencies
node_modules/
__pycache__/
*.pyc
*.pyo

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
desktop.ini

# Build
dist/
build/
*.log
*.tmp

# Secrets
*.pem
*.key
*.env
.env.local
.env.*.local

# Test coverage
coverage/
.nyc_output/

# Temporary files
*.tmp
*.temp
temp/
tmp/"
$gitignore | Out-File -FilePath ".gitignore" -Encoding utf8

# Summary
Write-Host ""
Write-Host "✅ Folder structure created successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Created at: $(Get-Location)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. cd $(Get-Location)" -ForegroundColor Gray
Write-Host "  2. git init" -ForegroundColor Gray
Write-Host "  3. git add ." -ForegroundColor Gray
Write-Host "  4. git commit -m 'Initial repository structure'" -ForegroundColor Gray