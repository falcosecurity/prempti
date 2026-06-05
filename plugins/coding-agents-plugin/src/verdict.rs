/// A verdict decision for a tool call.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Tool call allowed (no deny/ask rules matched) — Prempti actively
    /// approves. Interceptors render this as an explicit approval that skips
    /// the agent's own permission prompt.
    Allow,
    /// Tool call denied. Contains the reason string.
    Deny(String),
    /// Tool call requires user confirmation. Contains the reason string.
    Ask(String),
    /// Prempti steps aside on a no-rule-match: the agent's own permission
    /// system decides. Distinct from `Allow`, which actively approves and
    /// skips the prompt. Interceptors render this as "no decision" — empty
    /// stdout for Claude Code (its normal permission flow then applies) and a
    /// fall-through at Codex's `PermissionRequest` gate. Carries no reason:
    /// nothing matched, so there is nothing to explain.
    Defer,
}

impl Verdict {
    /// Escalate: deny > ask > {allow, defer}. Returns the more restrictive
    /// verdict. `Allow` and `Defer` are co-equal no-match floors — a single
    /// plugin instance resolves every no-match event with one floor (its
    /// configured `default_action`, or `defer` under monitor/passthrough), so
    /// they never actually compete; both simply lose to deny and ask.
    pub fn escalate(self, other: Verdict) -> Verdict {
        match (&self, &other) {
            (Verdict::Deny(_), _) => self,
            (_, Verdict::Deny(_)) => other,
            (Verdict::Ask(_), _) => self,
            (_, Verdict::Ask(_)) => other,
            _ => self,
        }
    }

    /// Serialize as the wire protocol response JSON.
    pub fn to_response_json(&self, id: &str) -> String {
        let (decision, reason) = match self {
            Verdict::Allow => ("allow", String::new()),
            Verdict::Deny(r) => ("deny", r.clone()),
            Verdict::Ask(r) => ("ask", r.clone()),
            Verdict::Defer => ("defer", String::new()),
        };
        // Use serde_json to ensure proper escaping of reason string.
        serde_json::json!({
            "id": id,
            "decision": decision,
            "reason": reason,
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(j: &str) -> serde_json::Value {
        serde_json::from_str(j).expect("parse verdict response JSON")
    }

    // ---- escalate: 3x3 matrix ---------------------------------------

    #[test]
    fn escalate_allow_allow_stays_allow() {
        assert!(matches!(
            Verdict::Allow.escalate(Verdict::Allow),
            Verdict::Allow
        ));
    }

    #[test]
    fn escalate_deny_beats_allow_either_order() {
        assert!(matches!(
            Verdict::Allow.escalate(Verdict::Deny("x".into())),
            Verdict::Deny(_)
        ));
        assert!(matches!(
            Verdict::Deny("x".into()).escalate(Verdict::Allow),
            Verdict::Deny(_)
        ));
    }

    #[test]
    fn escalate_ask_beats_allow_either_order() {
        assert!(matches!(
            Verdict::Allow.escalate(Verdict::Ask("x".into())),
            Verdict::Ask(_)
        ));
        assert!(matches!(
            Verdict::Ask("x".into()).escalate(Verdict::Allow),
            Verdict::Ask(_)
        ));
    }

    #[test]
    fn escalate_deny_beats_ask_either_order() {
        match Verdict::Ask("a".into()).escalate(Verdict::Deny("d".into())) {
            Verdict::Deny(s) => assert_eq!(s, "d"),
            v => panic!("expected Deny, got {:?}", v),
        }
        match Verdict::Deny("d".into()).escalate(Verdict::Ask("a".into())) {
            Verdict::Deny(s) => assert_eq!(s, "d"),
            v => panic!("expected Deny, got {:?}", v),
        }
    }

    #[test]
    fn escalate_first_deny_wins_when_both_deny() {
        // Escalate returns `self` when both are deny — the first reason wins.
        match Verdict::Deny("first".into()).escalate(Verdict::Deny("second".into())) {
            Verdict::Deny(s) => assert_eq!(s, "first"),
            v => panic!("expected Deny, got {:?}", v),
        }
    }

    #[test]
    fn escalate_first_ask_wins_when_both_ask() {
        match Verdict::Ask("first".into()).escalate(Verdict::Ask("second".into())) {
            Verdict::Ask(s) => assert_eq!(s, "first"),
            v => panic!("expected Ask, got {:?}", v),
        }
    }

    #[test]
    fn escalate_deny_beats_defer_either_order() {
        assert!(matches!(
            Verdict::Defer.escalate(Verdict::Deny("x".into())),
            Verdict::Deny(_)
        ));
        assert!(matches!(
            Verdict::Deny("x".into()).escalate(Verdict::Defer),
            Verdict::Deny(_)
        ));
    }

    #[test]
    fn escalate_ask_beats_defer_either_order() {
        assert!(matches!(
            Verdict::Defer.escalate(Verdict::Ask("x".into())),
            Verdict::Ask(_)
        ));
        assert!(matches!(
            Verdict::Ask("x".into()).escalate(Verdict::Defer),
            Verdict::Ask(_)
        ));
    }

    #[test]
    fn escalate_defer_is_a_floor_like_allow() {
        // Allow and Defer are co-equal floors: neither escalates over the
        // other, and a floor never wins against itself in a way that matters.
        assert!(matches!(
            Verdict::Defer.escalate(Verdict::Defer),
            Verdict::Defer
        ));
        // Mixing floors (which a single plugin instance never does in practice)
        // stays a floor — it must not produce a deny/ask out of thin air.
        assert!(matches!(
            Verdict::Allow.escalate(Verdict::Defer),
            Verdict::Allow | Verdict::Defer
        ));
        assert!(matches!(
            Verdict::Defer.escalate(Verdict::Allow),
            Verdict::Allow | Verdict::Defer
        ));
    }

    // ---- to_response_json -------------------------------------------

    #[test]
    fn response_allow_has_empty_reason() {
        let v = parse(&Verdict::Allow.to_response_json("id1"));
        assert_eq!(v["id"], "id1");
        assert_eq!(v["decision"], "allow");
        assert_eq!(v["reason"], "");
    }

    #[test]
    fn response_deny_includes_reason() {
        let v = parse(&Verdict::Deny("blocked".into()).to_response_json("id2"));
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "blocked");
    }

    #[test]
    fn response_ask_includes_reason() {
        let v = parse(&Verdict::Ask("confirm".into()).to_response_json("id3"));
        assert_eq!(v["decision"], "ask");
        assert_eq!(v["reason"], "confirm");
    }

    #[test]
    fn response_defer_has_empty_reason() {
        let v = parse(&Verdict::Defer.to_response_json("id4"));
        assert_eq!(v["id"], "id4");
        assert_eq!(v["decision"], "defer");
        assert_eq!(v["reason"], "");
    }

    #[test]
    fn response_escapes_quotes_and_newlines() {
        let tricky = "line1\n\"quoted\"\tvalue";
        let v = parse(&Verdict::Deny(tricky.into()).to_response_json("id"));
        assert_eq!(v["reason"], tricky);
    }
}
