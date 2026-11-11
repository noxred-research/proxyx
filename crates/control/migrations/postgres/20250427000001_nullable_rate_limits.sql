-- Make rate limit columns nullable so NULL means "inherit env defaults"
ALTER TABLE orgs ALTER COLUMN rate_limit_rpm DROP NOT NULL;
ALTER TABLE orgs ALTER COLUMN rate_limit_rpm DROP DEFAULT;
ALTER TABLE orgs ALTER COLUMN rate_limit_burst DROP NOT NULL;
ALTER TABLE orgs ALTER COLUMN rate_limit_burst DROP DEFAULT;
