// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Per-bucket token allocation ledger enforcing independent reservation caps for Review,
//! Assistants, and Authoring workloads (`docs/design/19`).

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;

use crate::queue::CODE_REV_TOKEN_BUDGET_EXCEEDED;

pub const REVIEW_BUDGET_SHARE_PCT: u64 = 80;
pub const ASSISTANTS_BUDGET_SHARE_PCT: u64 = 15;
pub const AUTHORING_BUDGET_SHARE_PCT: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetBucket {
    Review,
    Assistants,
    Authoring,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenAllocationLedger {
    pub total_budget: u64,
    pub review_used: u64,
    pub assistants_used: u64,
    pub authoring_used: u64,
    #[serde(default)]
    pub review_reserved: u64,
    #[serde(default)]
    pub assistants_reserved: u64,
    #[serde(default)]
    pub authoring_reserved: u64,
    pub review_skipped_count: u64,
}

impl TokenAllocationLedger {
    #[must_use]
    pub fn new(total_budget: u64) -> Self {
        Self {
            total_budget,
            review_used: 0,
            assistants_used: 0,
            authoring_used: 0,
            review_reserved: 0,
            assistants_reserved: 0,
            authoring_reserved: 0,
            review_skipped_count: 0,
        }
    }

    #[must_use]
    pub fn bucket_cap(&self, bucket: BudgetBucket) -> u64 {
        let share = match bucket {
            BudgetBucket::Review => REVIEW_BUDGET_SHARE_PCT,
            BudgetBucket::Assistants => ASSISTANTS_BUDGET_SHARE_PCT,
            BudgetBucket::Authoring => AUTHORING_BUDGET_SHARE_PCT,
        };
        self.total_budget.saturating_mul(share) / 100
    }

    #[must_use]
    pub fn bucket_used(&self, bucket: BudgetBucket) -> u64 {
        match bucket {
            BudgetBucket::Review => self.review_used,
            BudgetBucket::Assistants => self.assistants_used,
            BudgetBucket::Authoring => self.authoring_used,
        }
    }

    #[must_use]
    pub fn bucket_reserved(&self, bucket: BudgetBucket) -> u64 {
        match bucket {
            BudgetBucket::Review => self.review_reserved,
            BudgetBucket::Assistants => self.assistants_reserved,
            BudgetBucket::Authoring => self.authoring_reserved,
        }
    }

    #[must_use]
    pub fn total_reserved(&self) -> u64 {
        self.review_reserved
            .saturating_add(self.assistants_reserved)
            .saturating_add(self.authoring_reserved)
    }

    pub fn reserve(&mut self, bucket: BudgetBucket, tokens: u64) -> Result<(), CodedError> {
        let cap = self.bucket_cap(bucket);
        let projected_bucket = self
            .bucket_used(bucket)
            .saturating_add(self.bucket_reserved(bucket))
            .saturating_add(tokens);
        let total_used = self
            .review_used
            .saturating_add(self.assistants_used)
            .saturating_add(self.authoring_used)
            .saturating_add(self.total_reserved())
            .saturating_add(tokens);
        if projected_bucket > cap || total_used > self.total_budget {
            if bucket == BudgetBucket::Review {
                self.review_skipped_count = self.review_skipped_count.saturating_add(1);
            }
            return Err(CodedError::new(
                CODE_REV_TOKEN_BUDGET_EXCEEDED,
                format!("token reservation {tokens} exceeded {bucket:?} bucket or total cap"),
                "Defer lineage review or raise organisation token ceiling.",
            ));
        }
        match bucket {
            BudgetBucket::Review => {
                self.review_reserved = self.review_reserved.saturating_add(tokens);
            }
            BudgetBucket::Assistants => {
                self.assistants_reserved = self.assistants_reserved.saturating_add(tokens);
            }
            BudgetBucket::Authoring => {
                self.authoring_reserved = self.authoring_reserved.saturating_add(tokens);
            }
        }
        Ok(())
    }

    pub fn settle(
        &mut self,
        bucket: BudgetBucket,
        reserved_tokens: u64,
        actual_tokens: u64,
    ) -> Result<(), CodedError> {
        let cur_res = self.bucket_reserved(bucket);
        if reserved_tokens > cur_res {
            return Err(CodedError::new(
                CODE_REV_TOKEN_BUDGET_EXCEEDED,
                "cannot settle more tokens than reserved in bucket",
                "Pass exact reservation handle when settling tokens.",
            ));
        }
        let projected_bucket_used = self.bucket_used(bucket).saturating_add(actual_tokens);
        let total_next = self
            .review_used
            .saturating_add(self.assistants_used)
            .saturating_add(self.authoring_used)
            .saturating_add(self.total_reserved().saturating_sub(reserved_tokens))
            .saturating_add(actual_tokens);
        if projected_bucket_used > self.bucket_cap(bucket) || total_next > self.total_budget {
            return Err(CodedError::new(
                CODE_REV_TOKEN_BUDGET_EXCEEDED,
                "actual token settlement exceeded bucket or total budget",
                "Audit batch sizing.",
            ));
        }
        match bucket {
            BudgetBucket::Review => {
                self.review_reserved = self.review_reserved.saturating_sub(reserved_tokens);
                self.review_used = self.review_used.saturating_add(actual_tokens);
            }
            BudgetBucket::Assistants => {
                self.assistants_reserved = self.assistants_reserved.saturating_sub(reserved_tokens);
                self.assistants_used = self.assistants_used.saturating_add(actual_tokens);
            }
            BudgetBucket::Authoring => {
                self.authoring_reserved = self.authoring_reserved.saturating_sub(reserved_tokens);
                self.authoring_used = self.authoring_used.saturating_add(actual_tokens);
            }
        }
        Ok(())
    }

    pub fn record_skipped_lineage(&mut self) {
        self.review_skipped_count = self.review_skipped_count.saturating_add(1);
    }
}
