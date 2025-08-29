-- Remove role-permission links
DELETE FROM role_permissions WHERE role = 'blockjoy-admin' AND permission IN (
    'image-admin-add',
    'image-admin-get',
    'image-admin-list',
    'image-admin-list-archives',
    'image-admin-update-archive',
    'image-admin-update-image',
    'image-admin-add-property',
    'image-admin-update-property',
    'image-admin-delete-property',
    'image-admin-copy-properties'
);

-- Remove permissions (only if not used by other roles)
DELETE FROM permissions WHERE name IN (
    'image-admin-add',
    'image-admin-get',
    'image-admin-list',
    'image-admin-list-archives',
    'image-admin-update-archive',
    'image-admin-update-image',
    'image-admin-add-property',
    'image-admin-update-property',
    'image-admin-delete-property',
    'image-admin-copy-properties'
) AND name NOT IN (SELECT DISTINCT permission FROM role_permissions);