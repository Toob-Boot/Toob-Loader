-- +goose Down
-- +goose StatementBegin

-- Reverse order of creation to respect foreign key dependencies.

DROP INDEX IF EXISTS idx_device_events_device;
DROP TABLE IF EXISTS device_events;

DROP INDEX IF EXISTS assignments_one_open;
DROP TABLE IF EXISTS assignments;

DROP TABLE IF EXISTS devices;

DROP INDEX IF EXISTS releases_one_active;
DROP TABLE IF EXISTS releases;

DROP INDEX IF EXISTS artifacts_build_unique;
DROP TABLE IF EXISTS artifacts;

DROP TABLE IF EXISTS product_svn_floor;
DROP TABLE IF EXISTS products;

-- +goose StatementEnd
