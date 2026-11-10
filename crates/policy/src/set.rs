//! A validated set of policies and the effective policy per org and provider.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use common::types::{OrgId, ProviderId};

use crate::doc::{PolicyDoc, Scope};
use crate::effective::{EffectivePolicy, resolve};
use crate::error::PolicyError;

/// Effective policies of one org (or of every org without its own policy),
/// one per route-class policy plus the base.
struct Row {
    base: EffectivePolicy,
    by_provider: HashMap<ProviderId, EffectivePolicy>,
}

impl Row {
    fn get(&self, provider: Option<&ProviderId>) -> &EffectivePolicy {
        provider
            .and_then(|p| self.by_provider.get(p))
            .unwrap_or(&self.base)
    }
}

/// Every policy, merged and checked once. [`PolicySet::effective`] only looks
/// up. A clone shares the merged rows, so a reload that finds the policies
/// unchanged keeps the set it has instead of merging them again.
#[derive(Clone)]
pub struct PolicySet {
    inner: Arc<Rows>,
}

struct Rows {
    default_row: Row,
    orgs: HashMap<OrgId, Row>,
}

impl PolicySet {
    /// Check `docs` and merge them for every org and route class. Rejected: a
    /// name or `(scope, match)` used twice, `scope` and `match` that disagree,
    /// and any merged combination `resolve` refuses.
    pub fn from_docs(docs: Vec<PolicyDoc>) -> Result<Self, PolicyError> {
        let mut names = HashSet::new();
        let mut global: Option<&PolicyDoc> = None;
        let mut route_classes: Vec<(ProviderId, &PolicyDoc)> = Vec::new();
        let mut orgs: Vec<(OrgId, &PolicyDoc)> = Vec::new();
        let mut org_ids: HashSet<OrgId> = HashSet::new();

        for doc in &docs {
            if doc.name.is_empty() {
                return Err(scope_err(doc, "name must not be empty"));
            }
            if !names.insert(doc.name.as_str()) {
                return Err(PolicyError::DuplicateName(doc.name.clone()));
            }
            let duplicate = |key: &str| PolicyError::Duplicate {
                scope: doc.scope,
                key: key.to_owned(),
            };
            match (doc.scope, doc.target.as_deref()) {
                (Scope::Global, None) => {
                    if global.replace(doc).is_some() {
                        return Err(duplicate("*"));
                    }
                }
                (Scope::Global, Some(_)) => {
                    return Err(scope_err(doc, "a global policy takes no match"));
                }
                (Scope::RouteClass, Some(m)) => {
                    let id: ProviderId = m
                        .parse()
                        .map_err(|e| scope_err(doc, format!("match: {e}")))?;
                    if route_classes.iter().any(|(p, _)| *p == id) {
                        return Err(duplicate(m));
                    }
                    route_classes.push((id, doc));
                }
                (Scope::Org, Some(m)) => {
                    let id: OrgId = m
                        .parse()
                        .map_err(|e| scope_err(doc, format!("match: {e}")))?;
                    // Fair use is the provider's per-IP monthly allowance and an
                    // IP serves many orgs, so only global and route-class
                    // policies may set it: an org value would stop the IP for
                    // every org.
                    if doc.cost.fair_use_gb_per_ip_month.is_some()
                        || doc.limits.fair_use_gb_per_ip_month.is_some()
                    {
                        return Err(scope_err(
                            doc,
                            "fair_use_gb_per_ip_month is per IP and shared by every org; \
                             set it in a global or route_class policy",
                        ));
                    }
                    if !org_ids.insert(id.clone()) {
                        return Err(duplicate(m));
                    }
                    orgs.push((id, doc));
                }
                (Scope::RouteClass | Scope::Org, None) => {
                    return Err(scope_err(
                        doc,
                        format!("a {} policy needs match", doc.scope),
                    ));
                }
            }
        }

        let build_row = |org: Option<&PolicyDoc>| -> Result<Row, PolicyError> {
            let merge = |rc: Option<&PolicyDoc>| {
                let chain = [global, rc, org];
                let mut merged = PolicyDoc::default();
                for d in chain.into_iter().flatten() {
                    merged.overlay(d);
                }
                // The names are only for the error, so a set that is fine
                // (nearly every merge) does not build them.
                resolve(&merged, "").or_else(|_| {
                    let context = chain
                        .into_iter()
                        .flatten()
                        .map(|d| d.name.as_str())
                        .collect::<Vec<_>>()
                        .join(" + ");
                    resolve(
                        &merged,
                        if context.is_empty() {
                            "no policy"
                        } else {
                            &context
                        },
                    )
                })
            };
            Ok(Row {
                base: merge(None)?,
                by_provider: route_classes
                    .iter()
                    .map(|(p, d)| Ok((p.clone(), merge(Some(d))?)))
                    .collect::<Result<_, PolicyError>>()?,
            })
        };

        let default_row = build_row(None)?;
        let orgs = orgs
            .iter()
            .map(|(id, d)| Ok((id.clone(), build_row(Some(d))?)))
            .collect::<Result<_, PolicyError>>()?;
        Ok(Self {
            inner: Arc::new(Rows { default_row, orgs }),
        })
    }

    /// The policy for `org` on `provider`: global, then the provider's
    /// route-class policy, then the org's own, field by field. `None` or a
    /// provider without a route-class policy skips that step; an org without
    /// a policy gets the global and route-class values.
    pub fn effective(&self, org: &OrgId, provider: Option<&ProviderId>) -> &EffectivePolicy {
        self.inner
            .orgs
            .get(org)
            .unwrap_or(&self.inner.default_row)
            .get(provider)
    }

    /// The policy of an org that has none of its own: global, then
    /// `provider`'s route class.
    pub fn effective_default(&self, provider: Option<&ProviderId>) -> &EffectivePolicy {
        self.inner.default_row.get(provider)
    }

    /// Check every policy that can apply to `provider` (the base one, the
    /// route class's and each org's) against the longest session `provider`
    /// keeps: [`RotatingRules::check_life`]. For a rotating provider only.
    pub fn check_session_life(
        &self,
        provider: &ProviderId,
        provider_max: Duration,
    ) -> Result<(), PolicyError> {
        let rows = std::iter::once((None, &self.inner.default_row))
            .chain(self.inner.orgs.iter().map(|(org, row)| (Some(org), row)));
        for (org, row) in rows {
            row.get(Some(provider))
                .rotating
                .check_life(provider_max)
                .map_err(|reason| PolicyError::Invalid {
                    context: match org {
                        Some(org) => format!("the policies of org {org} on provider {provider}"),
                        None => format!("the default policies on provider {provider}"),
                    },
                    field: "rotating.min_remaining",
                    reason,
                })?;
        }
        Ok(())
    }
}

fn scope_err(doc: &PolicyDoc, reason: impl Into<String>) -> PolicyError {
    PolicyError::Scope {
        name: doc.name.clone(),
        reason: reason.into(),
    }
}
