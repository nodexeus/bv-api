# Implementation Plan

- [x] 1. Add S3 HEAD object support to store client
  - Add `head_object` import and error handling to `blockvisor-api/src/store/client.rs`
  - Implement `check_key_exists()` method using S3 `head_object()` operation
  - Add `CheckKeyExists` error variant to handle HEAD request failures
  - Write unit tests for key existence checking with valid and invalid keys
  - _Requirements: 2.1, 2.2_

- [x] 2. Implement archive existence validation method
  - Create `check_archive_exists()` method in `blockvisor-api/src/store/mod.rs`
  - Check for both `manifest-header.json` and `manifest-body.json` file existence
  - Use the new `check_key_exists()` method for efficient validation
  - Write unit tests for archive existence checking with complete and incomplete archives
  - _Requirements: 1.1, 2.1_

- [x] 3. Optimize data version discovery algorithm
  - Replace `list_with_delimiter()` approach in `data_versions()` method
  - Implement targeted version search using direct manifest file checks
  - Add reasonable bounds and consecutive miss limits to prevent infinite searching
  - Maintain descending sort order for version list compatibility
  - _Requirements: 1.1, 1.3_

- [x] 4. Add comprehensive error handling
  - Handle `HeadObjectError::NotFound` as non-existence (return false)
  - Propagate other HEAD request errors appropriately
  - Ensure error messages provide clear context for debugging
  - Test error scenarios including network failures and permission issues
  - _Requirements: 1.1, 3.3_

- [x] 5. Create integration tests for large archive scenarios
  - Test archive validation with 7000+ chunk scenarios
  - Verify that large archives are properly detected and validated
  - Compare performance before and after optimization
  - Test with real S3-compatible storage backend
  - _Requirements: 1.2, 2.2_

- [x] 6. Verify backward compatibility preservation
  - Run existing archive download integration tests
  - Ensure `download_manifest_header()` and `refresh_download_manifest()` work unchanged
  - Verify gRPC archive service responses remain consistent
  - Test with existing archive structures and workflows
  - _Requirements: 3.1, 3.2, 3.3_