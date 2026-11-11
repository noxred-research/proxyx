-- Make rate limit columns nullable so NULL means "inherit env defaults"
ALTER TABLE orgs
    MODIFY rate_limit_rpm INT NULL DEFAULT NULL,
    MODIFY rate_limit_burst INT NULL DEFAULT NULL;
