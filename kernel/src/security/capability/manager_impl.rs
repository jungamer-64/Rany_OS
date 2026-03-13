use super::*;

impl CapabilityManager {
    /// Create a new capability manager
    pub const fn new() -> Self {
        CapabilityManager {
            domains: PoisonLock::new(Vec::new()),
            bounding_set: PoisonLock::new(CAP_ALL),
            grants: PoisonLock::new(Vec::new()),
            next_grant_id: AtomicU64::new(1),
            in_flight: PoisonLock::new(Vec::new()),
            #[cfg(test)]
            fail_next_grant_for: PoisonLock::new(None),
        }
    }

    #[cfg(test)]
    pub(super) fn reset_for_tests(&self) {
        self.domains
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        *self
            .bounding_set
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = CAP_ALL;
        self.grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.next_grant_id.store(1, Ordering::Relaxed);
        self.in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        #[cfg(test)]
        {
            *self
                .fail_next_grant_for
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
        }
    }

    /// Get or create capabilities for a domain
    pub fn get_capabilities(&self, domain_id: u64) -> CapabilitySet {
        let domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        domains
            .iter()
            .find(|d| d.domain_id == domain_id)
            .map(|d| d.caps)
            .unwrap_or(CapabilitySet::empty())
    }

    /// Set capabilities for a domain
    pub fn set_capabilities(&self, domain_id: u64, caps: CapabilitySet) {
        let mut domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        let bounding = *self.bounding_set.lock().unwrap_or_else(|e| e.into_inner());

        // Apply bounding set
        let bounded_caps = CapabilitySet {
            effective: caps.effective & bounding,
            permitted: caps.permitted & bounding,
            inheritable: caps.inheritable & bounding,
            ambient: caps.ambient & bounding,
        };

        if let Some(domain) = domains.iter_mut().find(|d| d.domain_id == domain_id) {
            domain.caps = bounded_caps;
        } else {
            domains.push(DomainCapabilities {
                domain_id,
                caps: bounded_caps,
            });
        }
    }

    /// Check if domain has a capability
    pub fn has_capability(&self, domain_id: u64, cap: Capability) -> bool {
        self.get_capabilities(domain_id).has_capability(cap)
    }

    /// Grant a capability to a target domain on behalf of caller.
    pub fn grant_capability(
        &self,
        caller_domain: u64,
        target_domain: u64,
        cap: Capability,
    ) -> Result<(), CapabilityError> {
        // Check caller permissions
        let caller_caps = self.get_capabilities(caller_domain);
        if !self.has_capability(caller_domain, CAP_SYS_ADMIN) && !caller_caps.is_permitted(cap) {
            return Err(CapabilityError::NotPermitted);
        }

        // Add to permitted and effective (raise) for the target
        let mut caps = self.get_capabilities(target_domain);
        caps.permitted |= cap;
        caps.raise(cap)?;
        self.set_capabilities(target_domain, caps);
        Ok(())
    }

    pub(super) fn check_caller_allowed(&self, caller_domain: u64, cap: Capability) -> bool {
        if self.has_capability(caller_domain, CAP_SYS_ADMIN) {
            return true;
        }
        let caller_caps = self.get_capabilities(caller_domain);
        if caller_caps.is_permitted(cap) {
            return true;
        }
        let grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        grants
            .iter()
            .any(|t| t.target == caller_domain && t.cap == cap && t.delegatable)
    }

    /// Grant capability with options (expires, delegatable) and return a token id
    pub fn grant_capability_with_opts(
        &self,
        caller_domain: u64,
        target_domain: u64,
        cap: Capability,
        expires: Option<u64>,
        delegatable: bool,
    ) -> Result<u64, CapabilityError> {
        // Clean up expired tokens first
        self.expire_grants();

        if !self.check_caller_allowed(caller_domain, cap) {
            return Err(CapabilityError::NotPermitted);
        }

        // Test hook: optionally force a grant failure for a specific cap
        #[cfg(test)]
        {
            let mut f = self
                .fail_next_grant_for
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(fcap) = *f {
                if fcap == cap {
                    *f = None;
                    return Err(CapabilityError::InvalidCapability);
                }
            }
        }

        // Add to permitted and effective (raise) for the target
        let mut caps = self.get_capabilities(target_domain);
        caps.permitted |= cap;
        caps.raise(cap)?;
        self.set_capabilities(target_domain, caps);

        // Allocate token id and record grant
        let token_id = self.next_grant_id.fetch_add(1, Ordering::Relaxed);
        let token = GrantToken {
            id: token_id,
            cap,
            target: target_domain,
            issuer: caller_domain,
            expires,
            delegatable,
            revoked: false,
            revoked_at: None,
        };
        self.grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(token.clone());

        // Audit
        crate::security::audit::log_event(
            AuditEvent::new(AuditEventType::CapabilityCheck, caller_domain).message(format!(
                "grant cap {} -> domain {} (token={})",
                capability_name(cap),
                target_domain,
                token_id
            )),
        );

        Ok(token_id)
    }

    /// Revoke a grant by token id (issuer or CAP_SYS_ADMIN may revoke)
    pub fn revoke_grant(
        &self,
        caller_domain: u64,
        token_id: u64,
        force: bool,
    ) -> Result<(), CapabilityError> {
        // Clean expired first
        self.expire_grants();

        // Find token
        let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = grants.iter().position(|t| t.id == token_id) {
            // Authorization: issuer or sysadmin
            if caller_domain != grants[pos].issuer
                && !self.has_capability(caller_domain, CAP_SYS_ADMIN)
            {
                return Err(CapabilityError::NotPermitted);
            }

            // Acquire 'now'
            #[cfg(not(test))]
            let now = crate::task::current_tick();
            #[cfg(test)]
            let now = 0u64;

            if force {
                // Remove immediately
                let token = grants.remove(pos);
                drop(grants);

                // Remove the capability from the target domain
                let mut caps = self.get_capabilities(token.target);
                caps.drop_permanently(token.cap);
                self.set_capabilities(token.target, caps);

                crate::security::audit::log_event(
                    AuditEvent::new(AuditEventType::CapabilityCheck, caller_domain).message(
                        format!(
                            "revoke token {} cap {} from domain {} (force)",
                            token_id,
                            capability_name(token.cap),
                            token.target
                        ),
                    ),
                );

                Ok(())
            } else {
                // Mark as revoked; keep token record for reclamation visibility
                grants[pos].revoked = true;
                grants[pos].revoked_at = Some(now);
                let token = grants[pos].clone();
                drop(grants);

                // Remove capability from target (deny new operations immediately)
                let mut caps = self.get_capabilities(token.target);
                caps.drop_permanently(token.cap);
                self.set_capabilities(token.target, caps);

                crate::security::audit::log_event(
                    AuditEvent::new(AuditEventType::CapabilityCheck, caller_domain).message(
                        format!(
                            "mark token {} cap {} revoked for domain {}",
                            token_id,
                            capability_name(token.cap),
                            token.target
                        ),
                    ),
                );

                Ok(())
            }
        } else {
            Err(CapabilityError::InvalidCapability)
        }
    }

    /// List active grants targeting the given domain
    pub fn list_grants(&self, domain_id: u64) -> Vec<GrantToken> {
        self.expire_grants();
        let grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        grants
            .iter()
            .filter(|t| t.target == domain_id)
            .cloned()
            .collect()
    }

    /// Expire grants whose expiry <= current tick
    pub(super) fn expire_grants(&self) {
        #[cfg(not(test))]
        let now = crate::task::current_tick();
        #[cfg(test)]
        let now = 0u64;

        let mut expired: Vec<GrantToken> = Vec::new();
        {
            let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
            let mut i = 0;
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while i < grants.len() {
                if let Some(e) = grants[i].expires {
                    if e <= now {
                        expired.push(grants.remove(i));
                        continue;
                    }
                }
                i += 1;
            }
        }

        for token in expired {
            let mut caps = self.get_capabilities(token.target);
            caps.drop_permanently(token.cap);
            self.set_capabilities(token.target, caps);

            crate::security::audit::log_event(
                AuditEvent::new(AuditEventType::CapabilityCheck, 0).message(format!(
                    "expired token {} cap {} for domain {}",
                    token.id,
                    capability_name(token.cap),
                    token.target
                )),
            );
        }
    }

    /// Test helper: force the next grant of `cap` to fail once
    #[cfg(test)]
    pub fn force_fail_next_grant_for(&self, cap: Capability) {
        let mut f = self
            .fail_next_grant_for
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *f = Some(cap);
    }

    /// Require a capability (returns error if not present)
    pub fn require_capability(
        &self,
        domain_id: u64,
        cap: Capability,
    ) -> Result<(), CapabilityError> {
        if self.has_capability(domain_id, cap) {
            Ok(())
        } else {
            Err(CapabilityError::CapabilityRequired)
        }
    }

    /// Drop a capability from the bounding set (permanent)
    pub fn drop_from_bounding(&self, cap: Capability) {
        let mut bounding = self.bounding_set.lock().unwrap_or_else(|e| e.into_inner());
        *bounding &= !cap;
    }

    /// Get the bounding set
    pub fn bounding_set(&self) -> Capability {
        *self.bounding_set.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Remove domain
    pub fn remove_domain(&self, domain_id: u64) {
        let mut domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        domains.retain(|d| d.domain_id != domain_id);
    }

    /// Get reclamation status for a token (Active or Revoked with timestamp)
    pub fn reclamation_status(&self, token_id: u64) -> Option<ReclamationStatus> {
        let grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        grants.iter().find(|t| t.id == token_id).map(|t| {
            if t.revoked {
                ReclamationStatus::Revoked {
                    revoked_at: t.revoked_at.unwrap_or(0),
                }
            } else {
                ReclamationStatus::Active
            }
        })
    }

    /// Forcefully reclaim a revoked token (physically remove it)
    pub fn reclaim_token(&self, token_id: u64) -> Result<(), CapabilityError> {
        let in_flight = {
            let m = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            m.iter()
                .find(|(id, _)| *id == token_id)
                .map(|(_, cnt)| *cnt)
                .unwrap_or(0)
        };
        if in_flight > 0 {
            return Err(CapabilityError::ReclamationBusy);
        }

        let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = grants.iter().position(|t| t.id == token_id) {
            if !grants[pos].revoked {
                return Err(CapabilityError::InvalidCapability);
            }
            grants.remove(pos);
            let mut m = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(p) = m.iter().position(|(id, _)| *id == token_id) {
                m.remove(p);
            }
            Ok(())
        } else {
            Err(CapabilityError::InvalidCapability)
        }
    }

    /// Increment the in-flight counter for a token
    pub fn increment_in_flight(&self, token_id: u64) -> Result<(), CapabilityError> {
        {
            let grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(t) = grants.iter().find(|t| t.id == token_id) {
                if t.revoked {
                    return Err(CapabilityError::InvalidCapability);
                }
            } else {
                return Err(CapabilityError::InvalidCapability);
            }
        }

        let mut m = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pair) = m.iter_mut().find(|(id, _)| *id == token_id) {
            pair.1 += 1;
        } else {
            m.push((token_id, 1));
        }
        Ok(())
    }

    /// Decrement the in-flight counter for a token
    pub fn decrement_in_flight(&self, token_id: u64) -> Result<(), CapabilityError> {
        let mut m = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = m.iter().position(|(id, _)| *id == token_id) {
            if m[pos].1 == 0 {
                return Err(CapabilityError::InvalidCapability);
            }
            m[pos].1 -= 1;
            if m[pos].1 == 0 {
                m.remove(pos);
            }
            Ok(())
        } else {
            Err(CapabilityError::InvalidCapability)
        }
    }

    /// Current in-flight count for a token
    pub fn in_flight_count(&self, token_id: u64) -> u64 {
        let m = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        m.iter()
            .find(|(id, _)| *id == token_id)
            .map(|(_, cnt)| *cnt)
            .unwrap_or(0)
    }

    /// Reclaim revoked tokens that have no in-flight users
    pub fn reclaim_revoked_now(&self) {
        let mut to_reclaim: Vec<u64> = Vec::new();
        {
            let grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
            let in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            for t in grants.iter() {
                if t.revoked {
                    let cnt = in_flight
                        .iter()
                        .find(|(id, _)| *id == t.id)
                        .map(|(_, c)| *c)
                        .unwrap_or(0);
                    if cnt == 0 {
                        to_reclaim.push(t.id);
                    }
                }
            }
        }

        for id in to_reclaim {
            let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(pos) = grants.iter().position(|t| t.id == id && t.revoked) {
                grants.remove(pos);
                let mut m = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(p) = m.iter().position(|(tid, _)| *tid == id) {
                    m.remove(p);
                }

                crate::security::audit::log_event(
                    AuditEvent::new(AuditEventType::CapabilityCheck, 0)
                        .message(format!("reclaimed token {}", id)),
                );
            }
        }
    }

    /// Validate if a token is valid for a given capability
    pub fn validate_token(&self, _pid: u64, token_id: u64, required_cap: Capability) -> bool {
        let grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(token) = grants.iter().find(|t| t.id == token_id) {
            if token.cap == required_cap && !token.revoked {
                if let Some(exp) = token.expires {
                    #[cfg(not(test))]
                    let now = crate::task::current_tick();
                    #[cfg(test)]
                    let now = 0;
                    if now >= exp {
                        return false;
                    }
                }
                return true;
            }
        }
        false
    }
}
