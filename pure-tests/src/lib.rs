#![cfg_attr(not(test), allow(dead_code))]

use cap_harness::{grant, CapabilitySet, Manager, CAP_NET_BIND};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PureTier {
    PrRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PureGroup {
    Tools,
}

impl PureGroup {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Tools => "tools",
        }
    }
}

struct PureCase {
    id: &'static str,
    group: PureGroup,
    tier: PureTier,
    run: fn() -> bool,
}

macro_rules! pure_case {
    ($id:literal, $group:ident, $tier:ident, $fn_name:ident) => {
        PureCase {
            id: $id,
            group: PureGroup::$group,
            tier: PureTier::$tier,
            run: $fn_name,
        }
    };
}

static PURE_CASES: &[PureCase] = &[
    pure_case!(
        "tools.cap_harness_cross_grant",
        Tools,
        PrRequired,
        test_cap_harness_cross_grant
    ),
];

fn run_tier(tier: PureTier) {
    let mut total = 0usize;
    let mut passed = 0usize;

    for case in PURE_CASES {
        if case.tier != tier {
            continue;
        }

        total += 1;
        eprintln!("[pure-tests] case {} ({}) ...", case.id, case.group.as_str());
        if (case.run)() {
            passed += 1;
            eprintln!("[pure-tests] case {} ok", case.id);
        } else {
            panic!("pure test case failed: {}", case.id);
        }
    }

    eprintln!("[pure-tests] summary passed={passed} total={total}");
}

#[test]
fn pure_pr_required() {
    run_tier(PureTier::PrRequired);
}

fn test_cap_harness_cross_grant() -> bool {
    let mut manager = Manager::new();
    let caller = 10u64;
    let target = 20u64;

    manager.set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

    if grant(&mut manager, caller, "/net/bind", &[], target).is_err() {
        return false;
    }

    manager.has_capability(target, CAP_NET_BIND)
}
