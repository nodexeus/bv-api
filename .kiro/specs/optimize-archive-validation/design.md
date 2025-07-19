# Design Document

## Overview

This design optimizes archive validation by replacing expensive S3 listing operations with direct file existence checks. Instead of listing thousands of chunk files to find manifest files, the system will directly check for the existence of `manifest-header.json` and `manifest-body.json` files using S3 HEAD requests.

## Architecture

The optimization focuses on the `Store::data_versions()` method in `blockvisor-api/src/store/mod.rs`, which currently uses `list_with_delimiter()` to discover available data versions. The new approach will:

1. Use a more targeted strategy to find data versions
2. Directly check for manifest file existence rather than listing all objects
3. Maintain backward compatibility with existing archive download workflows

## Components and Interfaces

### Modified Components

#### Store Client (`blockvisor-api/src/store/client.rs`)

**New Method: `check_key_exists()`**
```rust
pub(super) async fn check_key_exists(&self, bucket: &str, key: &str) -> Result<bool, Error>
```
- Uses S3 `head_object()` to check if a key exists
- Returns `true` if the object exists, `false` if it doesn't
- More efficient than `get_object()` as it doesn't download content

#### Store (`blockvisor-api/src/store/mod.rs`)

**Modified Method: `data_versions()`**
- Replace `list_with_delimiter()` approach with direct manifest file checks
- Use a reasonable version range search strategy
- Check for both `manifest-header.json` and `manifest-body.json` existence

**New Method: `check_archive_exists()`**
```rust
pub async fn check_archive_exists(&self, store_key: &StoreKey, data_version: u64) -> Result<bool, Error>
```
- Directly check if both manifest files exist for a given version
- Used for validation without needing to list objects

## Data Models

No changes to existing data models. The optimization works with the current:
- `StoreKey` structure
- `ManifestHeader` and `ManifestBody` formats
- Archive storage layout: `{store_key}/{data_version}/manifest-{header|body}.json`

## Error Handling

### New Error Types
```rust
pub enum Error {
    // ... existing errors ...
    /// Failed to check key existence `{0}:{1}`: {2:?}
    CheckKeyExists(String, String, SdkError<HeadObjectError>),
}
```

### Error Mapping
- `HeadObjectError::NotFound` → `false` (key doesn't exist)
- Other `HeadObjectError` variants → propagate as `Error::CheckKeyExists`
- Maintain existing error handling for all other operations

## Implementation Strategy

### Phase 1: Add Key Existence Check
1. Add `head_object` import to client
2. Implement `check_key_exists()` method
3. Add corresponding error handling

### Phase 2: Optimize Version Discovery
1. Implement new `data_versions()` logic using direct checks
2. Add `check_archive_exists()` helper method
3. Use reasonable search strategy (e.g., check versions 1-100 initially, expand if needed)

### Phase 3: Testing and Validation
1. Test with large archives (7000+ chunks)
2. Verify performance improvements
3. Ensure backward compatibility

## Version Discovery Strategy

Instead of listing all objects, use a targeted search approach:

```rust
async fn data_versions(&self, store_key: &StoreKey) -> Result<Vec<u64>, Error> {
    let mut versions = Vec::new();
    let mut version = 1u64;
    let mut consecutive_misses = 0;
    const MAX_CONSECUTIVE_MISSES: u32 = 10;
    const MAX_VERSION_CHECK: u64 = 1000; // reasonable upper bound
    
    while version <= MAX_VERSION_CHECK && consecutive_misses < MAX_CONSECUTIVE_MISSES {
        if self.check_archive_exists(store_key, version).await? {
            versions.push(version);
            consecutive_misses = 0;
        } else {
            consecutive_misses += 1;
        }
        version += 1;
    }
    
    // Sort in descending order (latest first)
    versions.sort_by(|a, b| b.cmp(a));
    Ok(versions)
}
```

## Testing Strategy

### Unit Tests
- Test `check_key_exists()` with existing and non-existing keys
- Test `check_archive_exists()` with valid and invalid archives
- Test `data_versions()` with various version scenarios

### Integration Tests
- Test with real S3-compatible storage
- Verify large archive handling (7000+ chunks)
- Performance comparison: before vs after optimization

### Backward Compatibility Tests
- Ensure existing archive download workflows continue working
- Verify gRPC API responses remain unchanged
- Test with existing archive structures

## Performance Impact

### Expected Improvements
- **Reduced API Calls**: From 1+ `ListObjectsV2` calls to 2 `HeadObject` calls per version check
- **Faster Validation**: No need to process thousands of object listings
- **Lower Bandwidth**: HEAD requests don't transfer object content
- **Predictable Performance**: Not affected by number of chunks in archive

### Monitoring
- Add metrics for archive validation time
- Track S3 API call patterns
- Monitor error rates during validation