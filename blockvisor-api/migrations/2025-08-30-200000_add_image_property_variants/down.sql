-- Rollback variant filtering support

-- Drop the index
DROP INDEX IF EXISTS idx_image_properties_variants;

-- Remove the column
ALTER TABLE image_properties DROP COLUMN IF EXISTS variants;