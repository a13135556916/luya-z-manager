//! USB operation bindings and denials shared by the executor and HTTP adapters.
use luyaz_api::firmware::{ProbeResult, Support, UsbWriteDisposition, UsbWritePolicy};
use serde::Serialize;
use serde_json::Value;

pub(crate) fn capability(object: &str, method: &str) -> Option<&'static str> {
    if method != "set" {
        return None;
    }
    match object {
        "zwrt_bsp.usb" => Some("usb.mode.set"),
        "zwrt_bsp.typec" => Some("usb.attach.share"),
        "zwrt_bsp.powerbank" => Some("usb.attach.fast_charge"),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Denial {
    pub code: &'static str,
    pub message: String,
    pub policy: UsbWritePolicy,
    pub preflight: Option<ProbeResult>,
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl Denial {
    pub(crate) fn new(policy: UsbWritePolicy, code: &'static str, message: &str) -> Self {
        Self {
            code,
            message: message.into(),
            policy,
            preflight: None,
        }
    }
    pub(crate) fn status(&self) -> u16 {
        if matches!(self.code, "firmware_unsupported" | "usb_method_absent") {
            501
        } else {
            409
        }
    }
}

pub(crate) fn check(policy: &UsbWritePolicy, human: bool) -> Result<(), Box<Denial>> {
    let reason = if policy.assessment.status == Support::Unsupported {
        Some((
            "firmware_unsupported",
            "This firmware does not support this USB operation",
        ))
    } else if policy.disposition == UsbWriteDisposition::Denied {
        Some((
            "capability_blocked",
            "USB operation blocked by the current capability assessment",
        ))
    } else if !human && policy.disposition != UsbWriteDisposition::Ready {
        Some((
            "capability_unverified",
            "USB operation is unverified; an explicit human confirmation and fresh preflight are required",
        ))
    } else {
        None
    };
    match reason {
        Some((code, message)) => Err(Box::new(Denial::new(policy.clone(), code, message))),
        None => Ok(()),
    }
}

fn bit(v: &Value, key: &str) -> Option<i64> {
    v[key].as_i64().or_else(|| v[key].as_str()?.parse().ok())
}

/// Conditions checked from actual reads in the same executor job, never cached UI data.
pub(crate) fn attached(v: &Value) -> bool {
    bit(v, "cc_attch_state") == Some(1)
        && matches!(v["data_role"].as_str(), Some("host" | "device"))
}
/// The kernel's typec partner: present whenever something is in the port.
pub(crate) const TYPEC_PARTNER: &str = "/sys/class/typec/port0-partner";

/// `zwrt_bsp.typec list`'s `cc_attch_state` only moves on a plug event, so a cable that was in
/// before boot reads 0 for good (B31, 2026-11-03); the kernel's partner says it is in.
pub(crate) fn typec_partner_fix(v: &mut Value, partner: bool) {
    if partner && bit(v, "cc_attch_state") == Some(0) {
        v["cc_attch_state"] = serde_json::json!(1);
    }
}

/// The two typec writes reviewed: `DR_Swap device` (share) and `PR_Swap sink` (powered).
pub(crate) fn typec_reviewed(args: &Value) -> bool {
    let only = |k: &str| args.as_object().is_some_and(|o| o.keys().all(|x| x == k || x == "source_module"));
    (args["DR_Swap"] == "device" && only("DR_Swap")) || (args["PR_Swap"] == "sink" && only("PR_Swap"))
}

pub(crate) fn valid_read(object: &str, v: &Value) -> bool {
    match object {
        "zwrt_bsp.usb" => matches!(v["mode"].as_str(), Some("user" | "debug" | "mtp" | "rndis")),
        "zwrt_bsp.typec" => attached(v),
        "zwrt_bsp.powerbank" => matches!(bit(v, "state"), Some(0 | 1)),
        _ => false,
    }
}

/// Bind verified effects to the reviewed operation, never an arbitrary setter ACK.
pub(crate) fn effect(object: &str, args: &Value, read: &Value) -> Option<Value> {
    let fields = args.as_object()?;
    let key = match object {
        "zwrt_bsp.usb" => "mode",
        "zwrt_bsp.typec" if fields.contains_key("PR_Swap") => "PR_Swap",
        "zwrt_bsp.typec" => "DR_Swap",
        "zwrt_bsp.powerbank" => "state",
        _ => return None,
    };
    if fields.keys().any(|k| k != key && k != "source_module") {
        return None;
    }
    match object {
        "zwrt_bsp.usb"
            if valid_read(object, read)
                && args["mode"].as_str().is_some()
                && args["mode"] == read["mode"] =>
        {
            Some(serde_json::json!({"mode":read["mode"]}))
        }
        "zwrt_bsp.typec"
            if attached(read) && args["DR_Swap"] == "device" && read["data_role"] == "device" =>
        {
            Some(serde_json::json!({"data_role":"device","attached":true}))
        }
        "zwrt_bsp.typec"
            if attached(read) && args["PR_Swap"] == "sink" && read["power_role"] == "sink" =>
        {
            Some(serde_json::json!({"power_role":"sink","attached":true}))
        }
        "zwrt_bsp.powerbank"
            if matches!(bit(args, "state"), Some(0 | 1))
                && bit(args, "state") == bit(read, "state") =>
        {
            Some(serde_json::json!({"state":bit(read,"state")}))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn readback_cannot_verify_extra_fields_or_another_usb_operation() {
        let read = json!({"mode":"debug","state":1,"cc_attch_state":1,"data_role":"device"});
        assert!(effect("zwrt_bsp.usb", &json!({"mode":"debug"}), &read).is_some());
        for (object, args) in [
            ("zwrt_bsp.usb", json!({"mode":"debug","state":1})),
            (
                "zwrt_bsp.usb",
                json!({"mode":"debug","usb_port_switch":"1"}),
            ),
            (
                "zwrt_bsp.typec",
                json!({"DR_Swap":"device","PR_Swap":"source"}),
            ),
            ("zwrt_bsp.powerbank", json!({"state":1,"DR_Swap":"device"})),
        ] {
            assert!(effect(object, &args, &read).is_none());
        }
    }

    #[test]
    fn pr_swap_sink_is_reviewed_and_verified_alone() {
        assert!(typec_reviewed(&json!({"source_module":"x","DR_Swap":"device"})));
        assert!(typec_reviewed(&json!({"source_module":"x","PR_Swap":"sink"})));
        for args in [
            json!({"PR_Swap":"source"}),
            json!({"DR_Swap":"host"}),
            json!({"DR_Swap":"device","PR_Swap":"sink"}),
            json!({}),
        ] {
            assert!(!typec_reviewed(&args), "{args}");
        }
        let sink = json!({"cc_attch_state":1,"data_role":"device","power_role":"sink"});
        let source = json!({"cc_attch_state":1,"data_role":"device","power_role":"source"});
        assert!(effect("zwrt_bsp.typec", &json!({"PR_Swap":"sink"}), &sink).is_some());
        assert!(effect("zwrt_bsp.typec", &json!({"PR_Swap":"sink"}), &source).is_none());
    }

    #[test]
    fn partner_marks_a_cable_in_since_boot_attached() {
        let mut v = json!({"cc_attch_state":0,"data_role":"device","power_role":"sink"});
        typec_partner_fix(&mut v, false);
        assert_eq!(v["cc_attch_state"], 0);
        typec_partner_fix(&mut v, true);
        assert_eq!(v["cc_attch_state"], 1);
        // nothing read: left alone
        let mut e = json!({});
        typec_partner_fix(&mut e, true);
        assert_eq!(e, json!({}));
    }
}
