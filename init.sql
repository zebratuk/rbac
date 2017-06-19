CREATE TABLE IF NOT EXISTS acl_permission (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  title VARCHAR(1024) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS acl_role (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  title VARCHAR(1024) NOT NULL UNIQUE,
  parent_role_id BIGINT REFERENCES acl_role(id),
  is_superuser BOOLEAN NOT NULL DEFAULT FALSE,
  is_deletable BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE UNIQUE INDEX idx_acl_role_superuser ON acl_role (is_superuser) WHERE (is_superuser = TRUE);

CREATE TABLE IF NOT EXISTS acl_role_permission (
  role_id BIGINT NOT NULL REFERENCES acl_role(id) ON DELETE CASCADE,
  permission_id BIGINT NOT NULL REFERENCES acl_permission(id) ON DELETE CASCADE,
  UNIQUE(role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS account (
  id BIGSERIAL PRIMARY KEY,
  login VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(128) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  update_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS account_acl_role (
  account_id BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  role_id BIGINT NOT NULL REFERENCES acl_role(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS account_acl_permission (
  account_id BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  permission_id BIGINT NOT NULL REFERENCES acl_permission(id) ON DELETE RESTRICT
);

CREATE MATERIALIZED VIEW mvw_acl_roles AS
  WITH RECURSIVE cte_roles AS (
    SELECT
      id,
      name,
      title,
      parent_role_id,
      is_superuser,
      is_deletable,
      permissions
    FROM
      cte_role_permission
    WHERE parent_role_id IS NULL

    UNION ALL

    SELECT
      cp.id,
      cp.name,
      cp.title,
      cp.parent_role_id,
      cp.is_superuser,
      cp.is_deletable,
      ARRAY(SELECT DISTINCT UNNEST(cp.permissions || cr.permissions) ORDER BY 1) AS permissions
    FROM
      cte_roles cr,
      cte_role_permission cp
    WHERE cp.parent_role_id = cr.id
  ),
  cte_role_permission AS (
    SELECT
      a.*,
      ARRAY_REMOVE(ARRAY_AGG(ap.name), NULL) AS permissions
    FROM
      acl_role a
    LEFT JOIN acl_role_permission ar ON ar.role_id = a.id
    LEFT JOIN acl_permission ap ON ap.id = ar.permission_id
    GROUP BY a.id
  )
  SELECT * FROM cte_roles;

CREATE UNIQUE INDEX idx_mvw_acl_roles_id ON mvw_acl_roles(id);

CREATE MATERIALIZED VIEW mvw_account_acl_permission AS
  WITH cte_from_roles AS (
    SELECT DISTINCT
      a.account_id,
      UNNEST(ar.permissions) AS permission
    FROM
      account_acl_role a
    LEFT JOIN mvw_acl_roles ar ON ar.id = a.role_id

    UNION

    SELECT DISTINCT
      ap.account_id,
      p.name AS permission
    FROM
      account_acl_permission ap
    LEFT JOIN acl_permission p ON p.id = ap.permission_id
  )
  SELECT
    account_id,
    ARRAY_AGG(permission) AS permissions
  FROM
    cte_from_roles
  GROUP BY account_id;

CREATE UNIQUE INDEX idx_mvw_account_acl_permission_id ON mvw_account_acl_permission (account_id);

CREATE FUNCTION fn_refresh_acls() RETURNS TRIGGER AS $$
  BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mvw_acl_roles;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mvw_account_acl_permission;

    RETURN NULL;
  END
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_refresh_acl_permissions
  AFTER INSERT OR DELETE OR UPDATE ON acl_permission
  EXECUTE PROCEDURE fn_refresh_acls();

CREATE TRIGGER trg_refresh_acl_roles
  AFTER INSERT OR DELETE OR UPDATE ON acl_role
  EXECUTE PROCEDURE fn_refresh_acls();

CREATE TRIGGER trg_refresh_acl_roles_permissions
  AFTER INSERT OR DELETE OR UPDATE ON acl_role_permission
  EXECUTE PROCEDURE fn_refresh_acls();

CREATE FUNCTION fn_refresh_account_permissions() RETURNS TRIGGER AS $$
  BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mvw_account_acl_permission;

    RETURN NULL;
  END
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_refresh_account_acl_roles
  AFTER INSERT OR DELETE OR UPDATE ON account_acl_role
  EXECUTE PROCEDURE fn_refresh_account_permissions();

CREATE TRIGGER trg_refresh_account_acl_permissions
  AFTER INSERT OR DELETE OR UPDATE ON account_acl_permission
  EXECUTE PROCEDURE fn_refresh_account_permissions();
