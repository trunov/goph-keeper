-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS credentials
(
    id             SERIAL PRIMARY KEY,
    user_id        INTEGER REFERENCES users(id),
    data_type      SMALLINT,
    binary_data    BYTEA,
    meta_info      TEXT
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
