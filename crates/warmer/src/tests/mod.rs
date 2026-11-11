//! Behaviour tests with a loopback provider (see [`support`]). They need the
//! local Redis (DB 2) and Postgres and skip with a message when
//! `PROXYX_TEST_REDIS_URL` or `PROXYX_TEST_DATABASE_URL` is unset.

mod after_release;
mod boxes;
mod create;
mod customer;
mod hardening;
mod keepalive;
mod misc;
mod samples;
mod static_ips;
mod support;
