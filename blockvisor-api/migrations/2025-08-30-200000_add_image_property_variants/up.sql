-- Add variant filtering support to image properties
-- This allows properties to be scoped to specific protocol variants

-- Add the new column to store variants as JSONB array
ALTER TABLE image_properties ADD COLUMN variants JSONB;

-- Create GIN index for efficient querying of variant arrays
CREATE INDEX idx_image_properties_variants ON image_properties USING GIN (variants);

-- Add comment for documentation
COMMENT ON COLUMN image_properties.variants IS 'JSON array of variant keys where this property should be displayed. NULL means show for all variants.';