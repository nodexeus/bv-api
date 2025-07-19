# Requirements Document

## Introduction

The current archive validation system suffers from S3 pagination limitations when checking for snapshot archives with thousands of chunks. Instead of listing all objects to find manifest files, the system should directly check for the existence of specific manifest files to determine archive validity and available versions.

## Requirements

### Requirement 1

**User Story:** As a system administrator, I want archive validation to work reliably regardless of the number of chunks, so that large archives (7000+ chunks) are properly detected and used.

#### Acceptance Criteria

1. WHEN the system checks for archive existence THEN it SHALL directly check for manifest files instead of listing all objects
2. WHEN an archive has more than 1000 chunks THEN the system SHALL still detect the archive as valid
3. WHEN checking for available data versions THEN the system SHALL not be limited by S3's 1000-object pagination limit

### Requirement 2

**User Story:** As a developer, I want the archive validation process to be more efficient, so that it doesn't waste time and resources listing thousands of unnecessary files.

#### Acceptance Criteria

1. WHEN validating an archive THEN the system SHALL make direct S3 HEAD requests for manifest files
2. WHEN checking for data versions THEN the system SHALL avoid listing chunk files
3. WHEN an archive validation completes THEN it SHALL have made minimal S3 API calls

### Requirement 3

**User Story:** As a system operator, I want the existing archive download functionality to remain unchanged, so that current workflows continue to work.

#### Acceptance Criteria

1. WHEN downloading archive metadata THEN the system SHALL continue to use the existing `download_manifest_header` method
2. WHEN downloading archive chunks THEN the system SHALL continue to use the existing `refresh_download_manifest` method
3. WHEN the optimization is deployed THEN existing archive download workflows SHALL not be affected