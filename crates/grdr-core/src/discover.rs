// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::{AssuranceLevel, Device};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetCoverageSummary {
    pub total_agents: usize,
    pub guided_or_higher: usize,
    pub coverage_percent: usize,
}

pub fn summarize_coverage(devices: &[Device]) -> FleetCoverageSummary {
    let mut total_agents: usize = 0;
    let mut guided_or_higher: usize = 0;
    for device in devices {
        for agent in &device.agents {
            total_agents = total_agents.saturating_add(1);
            if agent.assurance_level >= AssuranceLevel::Al2Guided {
                guided_or_higher = guided_or_higher.saturating_add(1);
            }
        }
    }
    let coverage_percent = if total_agents == 0 {
        100
    } else {
        guided_or_higher
            .saturating_mul(100)
            .checked_div(total_agents)
            .unwrap_or(0)
    };
    FleetCoverageSummary {
        total_agents,
        guided_or_higher,
        coverage_percent,
    }
}
