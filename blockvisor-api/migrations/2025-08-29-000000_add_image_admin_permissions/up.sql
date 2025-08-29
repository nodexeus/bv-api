-- Insert image admin permissions
INSERT INTO permissions (name) VALUES 
    ('image-admin-add'),
    ('image-admin-get'),
    ('image-admin-list'),
    ('image-admin-list-archives'),
    ('image-admin-update-archive'),
    ('image-admin-update-image'),
    ('image-admin-add-property'),
    ('image-admin-update-property'),
    ('image-admin-delete-property'),
    ('image-admin-copy-properties')
ON CONFLICT (name) DO NOTHING;

-- Link image admin permissions to blockjoy-admin role
INSERT INTO role_permissions (role, permission) VALUES
    ('blockjoy-admin', 'image-admin-add'),
    ('blockjoy-admin', 'image-admin-get'),
    ('blockjoy-admin', 'image-admin-list'),
    ('blockjoy-admin', 'image-admin-list-archives'),
    ('blockjoy-admin', 'image-admin-update-archive'),
    ('blockjoy-admin', 'image-admin-update-image'),
    ('blockjoy-admin', 'image-admin-add-property'),
    ('blockjoy-admin', 'image-admin-update-property'),
    ('blockjoy-admin', 'image-admin-delete-property'),
    ('blockjoy-admin', 'image-admin-copy-properties')
ON CONFLICT (role, permission) DO NOTHING;