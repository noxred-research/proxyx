-- The pool gateway and the control plane each keep their own migration history, so they
-- need separate databases. POSTGRES_DB (proxyx) stays available for ad-hoc use.
CREATE DATABASE proxyx_pool;
CREATE DATABASE proxyx_control;
