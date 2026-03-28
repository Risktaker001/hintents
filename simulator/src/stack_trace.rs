// Copyright 2026 Erst Users
// SPDX-License-Identifier: Apache-2.0

//! Enhanced WASM stack trace generation.
//!
//! Exposes the Wasmi internal call stack directly on traps,
//! bypassing Soroban Host abstractions for low-level debugging.

#![allow(dead_code)]

use regex::Regex;
use serde::Serialize;

/// A single frame in a WASM call stack.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StackFrame {
    /// Index within the call stack (0 = innermost/trap site).
    pub index: usize,
    /// Function index in the WASM module, if known.
    pub func_index: Option<u32>,
    /// Demangled or raw function name, if available.
    pub func_name: Option<String>,
    /// Byte offset within the WASM module where the trap occurred.
    pub wasm_offset: Option<u64>,
    /// Module name, if the WASM has an embedded name section.
    pub module: Option<String>,
}

/// Categorised trap reason extracted from a raw error string.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum TrapKind {
    OutOfBoundsMemoryAccess,
    OutOfBoundsTableAccess,
    IntegerOverflow,
    IntegerDivisionByZero,
    InvalidConversionToInt,
    Unreachable,
    StackOverflow,
    IndirectCallTypeMismatch,
    UndefinedElement,
    HostError(String),
    Unknown(String),
}

/// Structured stack trace emitted on a WASM trap.
#[derive(Debug, Clone, Serialize)]
pub struct WasmStackTrace {
    /// Categorised trap reason.
    pub trap_kind: TrapKind,
    /// Raw error message from the host/runtime.
    pub raw_message: String,
    /// Ordered call stack frames (index 0 = trap site).
    pub frames: Vec<StackFrame>,
    /// Whether the Host error was unwound through Soroban abstractions.
    pub soroban_wrapped: bool,
}

impl Default for WasmStackTrace {
    fn default() -> Self {
        WasmStackTrace {
            trap_kind: TrapKind::Unknown(String::new()),
            raw_message: String::new(),
            frames: Vec::new(),
            soroban_wrapped: false,
        }
    }
}

impl WasmStackTrace {
    /// Build a stack trace by parsing a raw HostError debug representation.
    ///
    /// This extracts trap kind, function names, and offsets from the
    /// stringified error that Wasmi/Soroban produces.
    pub fn from_host_error(error_debug: &str) -> Self {
        let trap_kind = classify_trap(error_debug);
        let frames = extract_frames(error_debug);
        let soroban_wrapped = error_debug.contains("HostError")
            || error_debug.contains("ScError")
            || error_debug.contains("Error(WasmVm");

        WasmStackTrace {
            trap_kind,
            raw_message: error_debug.to_string(),
            frames,
            soroban_wrapped,
        }
    }

    /// Build a trace from a panic payload.
    pub fn from_panic(message: &str) -> Self {
        WasmStackTrace {
            trap_kind: TrapKind::Unknown(message.to_string()),
            raw_message: message.to_string(),
            frames: vec![],
            soroban_wrapped: false,
        }
    }

    /// Format the trace as a human-readable string.
    pub fn display(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!("Trap: {}\n", self.trap_kind_label()));

        if self.soroban_wrapped {
            out.push_str("  (error passed through Soroban Host layer)\n");
        }

        if self.frames.is_empty() {
            out.push_str("  <no frames captured>\n");
        } else {
            out.push_str("  Call stack (most recent call last):\n");
            for frame in &self.frames {
                out.push_str(&format!("    #{}: ", frame.index));
                if let Some(ref name) = frame.func_name {
                    out.push_str(name);
                } else if let Some(idx) = frame.func_index {
                    out.push_str(&format!("func[{}]", idx));
                } else {
                    out.push_str("<unknown>");
                }
                if let Some(offset) = frame.wasm_offset {
                    out.push_str(&format!(" @ 0x{:x}", offset));
                }
                if let Some(ref module) = frame.module {
                    out.push_str(&format!(" in {}", module));
                }
                out.push('\n');
            }
        }
        out
    }

    fn trap_kind_label(&self) -> &str {
        match &self.trap_kind {
            TrapKind::OutOfBoundsMemoryAccess => "out of bounds memory access",
            TrapKind::OutOfBoundsTableAccess => "out of bounds table access",
            TrapKind::IntegerOverflow => "integer overflow",
            TrapKind::IntegerDivisionByZero => "integer division by zero",
            TrapKind::InvalidConversionToInt => "invalid conversion to integer",
            TrapKind::Unreachable => "unreachable instruction executed",
            TrapKind::StackOverflow => "stack overflow",
            TrapKind::IndirectCallTypeMismatch => "indirect call type mismatch",
            TrapKind::UndefinedElement => "undefined table element",
            TrapKind::HostError(_) => "host error",
            TrapKind::Unknown(_) => "unknown trap",
        }
    }

    /// Get the WASM offset of the most recent frame (the trap site), if known.
    pub fn offset(&self) -> Option<u64> {
        self.frames.first().and_then(|f| f.wasm_offset)
    }
}

/// Regex patterns for frame extraction.
///
/// These patterns are compiled once at module initialization for efficiency.
mod frame_patterns {
    use regex::Regex;

    /// Matches lines with a leading index:
    /// - `0: func[42] @ 0xa3c`
    /// - `1: module::function @ 0xb20`
    /// - `#0: func[5]`
    /// - `0: func[42] @ 1234` (decimal offset)
    pub static NUMBERED_FRAME: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"^#?(\d+):\s*(?:(?:func\[(\d+)\])|(<[^>]+>)|([a-zA-Z_][a-zA-Z0-9_:]*(?:::[a-zA-Z_][a-zA-Z0-9_:]*)*))(?:\s+@\s+(?:0x([0-9a-fA-F]+)|(\d+)))?")
                .expect("failed to compile NUMBERED_FRAME regex")
        });

    /// Matches bare frames without a leading index (for continued backtraces):
    /// - `func[42] @ 0xa3c`
    /// - `<module>::function @ 0xb20`
    /// - `some_function @ 0x100`
    pub static BARE_FRAME: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"^(?:func\[(\d+)\]|(<[^>]+>)|([a-zA-Z_][a-zA-Z0-9_:]*(?:::[a-zA-Z_][a-zA-Z0-9_:]*)*))(?:\s+@\s+(?:0x([0-9a-fA-F]+)|(\d+)))?")
                .expect("failed to compile BARE_FRAME regex")
        });

    /// Matches various trap header formats:
    /// - `wasm backtrace:`
    /// - `wasm trace:`
    /// - `backtrace:`
    /// - `   0:` (starts with number + colon on otherwise empty line)
    pub static BACKTRACE_HEADER: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"(?i)^\s*(?:wasm\s+)?(?:back)?trace:\s*$")
                .expect("failed to compile BACKTRACE_HEADER regex")
        });

    /// Matches frame content after index has been stripped.
    /// Used for continuing to parse frames after the numbered frame regex.
    pub static FRAME_CONTENT: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"^(?:func\[(\d+)\]|(<[^>]+>)|([a-zA-Z_][a-zA-Z0-9_:]*(?:::[a-zA-Z_][a-zA-Z0-9_:]*)*))(?:\s+@\s+(?:0x([0-9a-fA-F]+)|(\d+)))?$")
                .expect("failed to compile FRAME_CONTENT regex")
        });
}

/// Regex patterns for trap classification.
///
/// Uses case-insensitive matching to handle various error string formats.
mod trap_patterns {
    use regex::Regex;

    pub static OUT_OF_BOUNDS_MEMORY: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"(?i)out\s+of\s+bounds\s+memory").expect("failed to compile OOB memory regex")
        });

    pub static OUT_OF_BOUNDS_TABLE: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"(?i)out\s+of\s+bounds\s+table").expect("failed to compile OOB table regex")
        });

    pub static INTEGER_OVERFLOW: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"(?i)integer\s+overflow").expect("failed to compile overflow regex")
        });

    pub static DIVISION_BY_ZERO: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"(?i)(?:integer\s+)?division\s+by\s+zero").expect("failed to compile div/0 regex")
        });

    pub static INVALID_CONVERSION: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"(?i)invalid\s+conversion\s+to\s+int").expect("failed to compile conversion regex")
        });

    pub static UNREACHABLE: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"(?i)unreachable").expect("failed to compile unreachable regex")
        });

    pub static STACK_OVERFLOW: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"(?i)(?:call\s+stack\s+exhausted|stack\s+overflow)").expect("failed to compile stack overflow regex")
        });

    pub static INDIRECT_CALL_MISMATCH: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"(?i)indirect\s+call\s+type\s+mismatch").expect("failed to compile indirect call regex")
        });

    pub static UNDEFINED_ELEMENT: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"(?i)(?:undefined|uninitialized)\s+element").expect("failed to compile undefined element regex")
        });

    pub static HOST_ERROR: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| {
            Regex::new(r"(?i)host(?:error)?").expect("failed to compile host error regex")
        });
}

/// Classify a raw error string into a known trap kind using regex patterns.
fn classify_trap(msg: &str) -> TrapKind {
    if trap_patterns::OUT_OF_BOUNDS_MEMORY.is_match(msg) {
        TrapKind::OutOfBoundsMemoryAccess
    } else if trap_patterns::OUT_OF_BOUNDS_TABLE.is_match(msg) {
        TrapKind::OutOfBoundsTableAccess
    } else if trap_patterns::INTEGER_OVERFLOW.is_match(msg) {
        TrapKind::IntegerOverflow
    } else if trap_patterns::DIVISION_BY_ZERO.is_match(msg) {
        TrapKind::IntegerDivisionByZero
    } else if trap_patterns::INVALID_CONVERSION.is_match(msg) {
        TrapKind::InvalidConversionToInt
    } else if trap_patterns::UNREACHABLE.is_match(msg) {
        TrapKind::Unreachable
    } else if trap_patterns::STACK_OVERFLOW.is_match(msg) {
        TrapKind::StackOverflow
    } else if trap_patterns::INDIRECT_CALL_MISMATCH.is_match(msg) {
        TrapKind::IndirectCallTypeMismatch
    } else if trap_patterns::UNDEFINED_ELEMENT.is_match(msg) {
        TrapKind::UndefinedElement
    } else if trap_patterns::HOST_ERROR.is_match(msg) {
        TrapKind::HostError(msg.to_string())
    } else {
        TrapKind::Unknown(msg.to_string())
    }
}

/// Extract call stack frames from the stringified Wasmi/HostError output.
///
/// Wasmi and Soroban format trap backtraces as lines like:
///   `  0: func[42] @ 0xa3c`
///   `  1: <module_name>::function_name @ 0xb20`
///   `wasm backtrace:`
///   `  0: my_contract::transfer`
///
/// We parse these into structured `StackFrame` values using regex for robustness.
fn extract_frames(error_debug: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    let mut in_backtrace = false;
    let mut expected_index: usize = 0;

    for line in error_debug.lines() {
        let trimmed = line.trim();

        // Check for backtrace header
        if frame_patterns::BACKTRACE_HEADER.is_match(trimmed) {
            in_backtrace = true;
            expected_index = 0;
            continue;
        }

        // Try numbered frame pattern first
        if let Some(captures) = frame_patterns::NUMBERED_FRAME.captures(trimmed) {
            if let Some(frame) = parse_frame_from_captures(&captures, in_backtrace) {
                frames.push(frame);
                expected_index = frames.len();
                in_backtrace = true;
                continue;
            }
        }

        // If we're in a backtrace section, try bare frame pattern
        if in_backtrace {
            if let Some(captures) = frame_patterns::BARE_FRAME.captures(trimmed) {
                if let Some(mut frame) = parse_bare_frame_from_captures(&captures, expected_index) {
                    // Only add if we actually extracted something meaningful
                    if frame.func_name.is_some() || frame.func_index.is_some() {
                        frame.index = expected_index;
                        frames.push(frame);
                        expected_index += 1;
                    }
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                // Empty or non-frame line might indicate end of backtrace
                if !frame_patterns::FRAME_CONTENT.is_match(trimmed) {
                    in_backtrace = false;
                }
            }
        }
    }

    frames
}

/// Parse frame data from regex captures.
fn parse_frame_from_captures(captures: &regex::Captures, in_backtrace: bool) -> Option<StackFrame> {
    // Get index if present
    let index = captures.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);

    // Get function index (group 2) or module path (group 3) or function name (group 4)
    let func_index = captures.get(2).and_then(|m| m.as_str().parse().ok());
    let module = captures.get(3).map(|m| m.as_str().trim_start_matches('<').trim_end_matches('>').to_string());
    let func_name = captures.get(4).map(|m| m.as_str().to_string());

    // Get offset (hex group 5 or decimal group 6)
    let wasm_offset = captures.get(5)
        .and_then(|m| u64::from_str_radix(m.as_str(), 16).ok())
        .or_else(|| captures.get(6).and_then(|m| m.as_str().parse().ok()));

    // Only return frame if we have something meaningful
    if func_index.is_some() || func_name.is_some() || wasm_offset.is_some() {
        Some(StackFrame {
            index,
            func_index,
            func_name,
            wasm_offset,
            module,
        })
    } else if in_backtrace {
        // In backtrace context, even partial frames might be valid
        Some(StackFrame {
            index,
            func_index: None,
            func_name: None,
            wasm_offset: None,
            module,
        })
    } else {
        None
    }
}

/// Parse bare frame (no leading index) from regex captures.
fn parse_bare_frame_from_captures(captures: &regex::Captures, index: usize) -> Option<StackFrame> {
    // Get function index (group 1) or module path (group 2) or function name (group 3)
    let func_index = captures.get(1).and_then(|m| m.as_str().parse().ok());
    let module = captures.get(2).map(|m| m.as_str().trim_start_matches('<').trim_end_matches('>').to_string());
    let func_name = captures.get(3).map(|m| m.as_str().to_string());

    // Get offset (hex group 4 or decimal group 5)
    let wasm_offset = captures.get(4)
        .and_then(|m| u64::from_str_radix(m.as_str(), 16).ok())
        .or_else(|| captures.get(5).and_then(|m| m.as_str().parse().ok()));

    if func_index.is_some() || func_name.is_some() {
        Some(StackFrame {
            index,
            func_index,
            func_name,
            wasm_offset,
            module,
        })
    } else {
        None
    }
}

/// Public helper: decode a raw error string into a human-readable description
/// that includes the trap kind. Used by `main.rs` for backward compatibility.
#[allow(dead_code)]
pub fn decode_error(msg: &str) -> String {
    let trace = WasmStackTrace::from_host_error(msg);
    let label = trace.trap_kind_label();

    if label != "unknown trap" {
        format!("VM Trap: {} -- {}", capitalise_first(label), msg)
    } else {
        format!("Error: {}", msg)
    }
}

#[allow(dead_code)]
fn capitalise_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_oob_memory() {
        let kind = classify_trap("Error: Wasm Trap: out of bounds memory access");
        assert_eq!(kind, TrapKind::OutOfBoundsMemoryAccess);
    }

    #[test]
    fn test_classify_unreachable() {
        let kind = classify_trap("wasm trap: unreachable");
        assert_eq!(kind, TrapKind::Unreachable);
    }

    #[test]
    fn test_classify_stack_overflow() {
        let kind = classify_trap("call stack exhausted");
        assert_eq!(kind, TrapKind::StackOverflow);
    }

    #[test]
    fn test_classify_division_by_zero() {
        let kind = classify_trap("integer division by zero");
        assert_eq!(kind, TrapKind::IntegerDivisionByZero);
    }

    #[test]
    fn test_classify_host_error() {
        let kind = classify_trap("HostError: contract call failed");
        assert!(matches!(kind, TrapKind::HostError(_)));
    }

    #[test]
    fn test_classify_unknown() {
        let kind = classify_trap("something completely unexpected");
        assert!(matches!(kind, TrapKind::Unknown(_)));
    }

    #[test]
    fn test_extract_numbered_frames() {
        let input = "wasm backtrace:\n  0: func[42] @ 0xa3c\n  1: func[7] @ 0xb20";
        let frames = extract_frames(input);

        assert_eq!(frames.len(), 2);

        assert_eq!(frames[0].index, 0);
        assert_eq!(frames[0].func_index, Some(42));
        assert_eq!(frames[0].wasm_offset, Some(0xa3c));

        assert_eq!(frames[1].index, 1);
        assert_eq!(frames[1].func_index, Some(7));
        assert_eq!(frames[1].wasm_offset, Some(0xb20));
    }

    #[test]
    fn test_extract_named_frames() {
        let input =
            "trace:\n  0: soroban_token::transfer @ 0x100\n  1: soroban_sdk::invoke @ 0x200";
        let frames = extract_frames(input);

        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].func_name,
            Some("soroban_token::transfer".to_string())
        );
        assert_eq!(frames[0].wasm_offset, Some(0x100));
    }

    #[test]
    fn test_extract_no_frames() {
        let input = "simple error message without any stack frames";
        let frames = extract_frames(input);
        assert!(frames.is_empty());
    }

    #[test]
    fn test_from_host_error_soroban_wrapped() {
        let trace = WasmStackTrace::from_host_error(
            "HostError: Error(WasmVm, InternalError)\n  0: func[5] @ 0x42",
        );
        assert!(trace.soroban_wrapped);
        assert_eq!(trace.frames.len(), 1);
        assert_eq!(trace.frames[0].func_index, Some(5));
    }

    #[test]
    fn test_from_host_error_not_soroban_wrapped() {
        let trace = WasmStackTrace::from_host_error("wasm trap: unreachable\n  0: func[10]");
        assert!(!trace.soroban_wrapped);
        assert_eq!(trace.trap_kind, TrapKind::Unreachable);
    }

    #[test]
    fn test_from_panic() {
        let trace = WasmStackTrace::from_panic("assertion failed");
        assert!(trace.frames.is_empty());
        assert!(!trace.soroban_wrapped);
        assert!(matches!(trace.trap_kind, TrapKind::Unknown(_)));
    }

    #[test]
    fn test_display_with_frames() {
        let trace = WasmStackTrace {
            trap_kind: TrapKind::OutOfBoundsMemoryAccess,
            raw_message: "test".to_string(),
            frames: vec![
                StackFrame {
                    index: 0,
                    func_index: Some(42),
                    func_name: None,
                    wasm_offset: Some(0xa3c),
                    module: None,
                },
                StackFrame {
                    index: 1,
                    func_index: None,
                    func_name: Some("my_contract::transfer".to_string()),
                    wasm_offset: Some(0xb20),
                    module: Some("token".to_string()),
                },
            ],
            soroban_wrapped: false,
        };

        let output = trace.display();
        assert!(output.contains("out of bounds memory access"));
        assert!(output.contains("func[42]"));
        assert!(output.contains("0xa3c"));
        assert!(output.contains("my_contract::transfer"));
        assert!(output.contains("in token"));
    }

    #[test]
    fn test_display_empty_frames() {
        let trace = WasmStackTrace::from_panic("boom");
        let output = trace.display();
        assert!(output.contains("<no frames captured>"));
    }

    #[test]
    fn test_display_soroban_wrapped() {
        let trace = WasmStackTrace::from_host_error("HostError: something");
        let output = trace.display();
        assert!(output.contains("Soroban Host layer"));
    }

    #[test]
    fn test_decode_error_known_trap() {
        let msg = decode_error("Error: Wasm Trap: out of bounds memory access");
        assert!(msg.contains("VM Trap: Out of bounds memory access"));
    }

    #[test]
    fn test_decode_error_unknown() {
        let msg = decode_error("some random error");
        assert!(msg.starts_with("Error:"));
    }

    #[test]
    fn test_frame_with_offset_no_hex_prefix() {
        let input = "  0: func[1] @ 1234";
        let frames = extract_frames(input);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].wasm_offset, Some(1234));
    }

    #[test]
    fn test_classify_table_access() {
        assert_eq!(
            classify_trap("out of bounds table access"),
            TrapKind::OutOfBoundsTableAccess
        );
    }

    #[test]
    fn test_classify_indirect_call_mismatch() {
        assert_eq!(
            classify_trap("indirect call type mismatch"),
            TrapKind::IndirectCallTypeMismatch
        );
    }

    #[test]
    fn test_capitalise_first() {
        assert_eq!(capitalise_first("hello"), "Hello");
    }

    // ============================================================================
    // Additional regex-based parsing tests
    // ============================================================================

    #[test]
    fn test_extract_frames_with_hash_prefix() {
        let input = "#0: func[42] @ 0xa3c\n#1: func[7]";
        let frames = extract_frames(input);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].func_index, Some(42));
        assert_eq!(frames[1].func_index, Some(7));
    }

    #[test]
    fn test_extract_frames_with_module_path() {
        let input = "wasm backtrace:\n  0: <my_contract>::transfer @ 0x100";
        let frames = extract_frames(input);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].module, Some("my_contract".to_string()));
        assert_eq!(frames[0].func_name, Some("transfer".to_string()));
    }

    #[test]
    fn test_extract_frames_mixed_formats() {
        let input = r#"Error: Wasm Trap: unreachable
wasm backtrace:
  0: func[1] @ 0x100
  1: contract::process @ 0x200
  2: func[5]"#;
        let frames = extract_frames(input);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].func_index, Some(1));
        assert_eq!(frames[0].wasm_offset, Some(0x100));
        assert_eq!(frames[1].func_name, Some("contract::process".to_string()));
        assert_eq!(frames[2].func_index, Some(5));
    }

    #[test]
    fn test_classify_variations() {
        // Test various case and whitespace variations
        assert_eq!(
            classify_trap("OUT OF BOUNDS MEMORY ACCESS"),
            TrapKind::OutOfBoundsMemoryAccess
        );
        assert_eq!(
            classify_trap("Out   of   Bounds   Memory"),
            TrapKind::OutOfBoundsMemoryAccess
        );
        assert_eq!(
            classify_trap("INTEGER OVERFLOW"),
            TrapKind::IntegerOverflow
        );
        assert_eq!(
            classify_trap("division by zero"),
            TrapKind::IntegerDivisionByZero
        );
    }

    #[test]
    fn test_extract_frames_complex_module_paths() {
        let input = "backtrace:\n  0: soroban_auth::signature::verify @ 0xabc\n  1: my::deeply::nested::module::function @ 0xdef";
        let frames = extract_frames(input);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].func_name, Some("soroban_auth::signature::verify".to_string()));
        assert_eq!(frames[1].func_name, Some("my::deeply::nested::module::function".to_string()));
    }

    #[test]
    fn test_extract_frames_no_offset() {
        let input = "wasm backtrace:\n  0: func[42]\n  1: my_function";
        let frames = extract_frames(input);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].func_index, Some(42));
        assert_eq!(frames[0].wasm_offset, None);
        assert_eq!(frames[1].func_name, Some("my_function".to_string()));
    }

    #[test]
    fn test_extract_frames_preserves_order() {
        let input = "wasm backtrace:\n  0: func[3]\n  1: func[2]\n  2: func[1]\n  3: func[0]";
        let frames = extract_frames(input);
        assert_eq!(frames.len(), 4);
        for (i, frame) in frames.iter().enumerate() {
            assert_eq!(frame.index, i);
            assert_eq!(frame.func_index, Some((3 - i) as u32));
        }
    }

    #[test]
    fn test_wasm_stack_trace_default() {
        let trace = WasmStackTrace::default();
        assert!(trace.frames.is_empty());
        assert!(!trace.soroban_wrapped);
        assert!(matches!(trace.trap_kind, TrapKind::Unknown(_)));
    }
}

// ============================================================================
// Property-based tests using proptest
// ============================================================================

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy for generating valid function names
    fn valid_function_name() -> impl Strategy<Value = String> {
        // Generate valid Rust-style function/module names
        prop::string::string_regex(r"[a-z][a-z0-9_]{0,30}").unwrap()
    }

    /// Strategy for generating valid module paths
    fn valid_module_path() -> impl Strategy<Value = String> {
        (1..=3usize)
            .prop_map(|parts| {
                let path: Vec<String> = (0..parts)
                    .map(|_| valid_function_name().prop_generate())
                    .collect();
                path.join("::")
            })
    }

    /// Strategy for generating wasm offsets (hex or decimal)
    fn wasm_offset() -> impl Strategy<Value = u64> {
        // Generate offsets that are reasonable for WASM
        (0u64..1_000_000u64)
    }

    /// Generate a frame string in numbered format
    fn numbered_frame_string(index: usize, func_index: Option<u32>, func_name: Option<String>, offset: Option<u64>) -> String {
        let mut line = format!("  {}: ", index);
        
        if let Some(idx) = func_index {
            line.push_str(&format!("func[{}]", idx));
        } else if let Some(name) = func_name {
            line.push_str(&name);
        } else {
            line.push_str("unknown");
        }
        
        if let Some(off) = offset {
            line.push_str(&format!(" @ 0x{:x}", off));
        }
        
        line
    }

    /// Strategy for generating valid trap messages
    fn trap_message() -> impl Strategy<Value = (String, TrapKind)> {
        prop::sample::select(vec![
            ("out of bounds memory access".to_string(), TrapKind::OutOfBoundsMemoryAccess),
            ("Out of bounds memory".to_string(), TrapKind::OutOfBoundsMemoryAccess),
            ("Out Of Bounds Table Access".to_string(), TrapKind::OutOfBoundsTableAccess),
            ("integer overflow".to_string(), TrapKind::IntegerOverflow),
            ("Integer Overflow".to_string(), TrapKind::IntegerOverflow),
            ("integer division by zero".to_string(), TrapKind::IntegerDivisionByZero),
            ("division by zero".to_string(), TrapKind::IntegerDivisionByZero),
            ("invalid conversion to int".to_string(), TrapKind::InvalidConversionToInt),
            ("unreachable".to_string(), TrapKind::Unreachable),
            ("WASM TRAP: unreachable".to_string(), TrapKind::Unreachable),
            ("call stack exhausted".to_string(), TrapKind::StackOverflow),
            ("stack overflow".to_string(), TrapKind::StackOverflow),
            ("indirect call type mismatch".to_string(), TrapKind::IndirectCallTypeMismatch),
            ("undefined element".to_string(), TrapKind::UndefinedElement),
            ("uninitialized element".to_string(), TrapKind::UndefinedElement),
            ("HostError: something happened".to_string(), TrapKind::HostError("HostError: something happened".to_string())),
            ("host error occurred".to_string(), TrapKind::HostError("host error occurred".to_string())),
        ])
    }

    proptest! {
        /// Property test: extracting frames from a known format preserves indices
        #[test]
        fn prop_extract_preserves_frame_indices(indices: Vec<usize>) {
            // Filter to reasonable indices and ensure uniqueness for this test
            let indices: Vec<usize> = indices.into_iter().take(10).collect();
            if indices.is_empty() {
                return Ok(());
            }
            
            let mut input = String::from("wasm backtrace:\n");
            for (i, &idx) in indices.iter().enumerate() {
                input.push_str(&numbered_frame_string(i, Some(idx as u32), None, None));
                input.push('\n');
            }
            
            let frames = extract_frames(&input);
            assert_eq!(frames.len(), indices.len());
            for (i, frame) in frames.iter().enumerate() {
                assert_eq!(frame.index, i);
                assert_eq!(frame.func_index, Some(indices[i] as u32));
            }
        }

        /// Property test: frames with various offset formats parse correctly
        #[test]
        fn prop_offset_parsing(hex_offset: u64, dec_offset: u64) {
            // Limit to reasonable values
            let hex_off = hex_offset % 1_000_000;
            let dec_off = (dec_offset % 1_000_000) as u64;
            
            // Test hex offset
            let input = format!("  0: func[1] @ 0x{:x}", hex_off);
            let frames = extract_frames(&input);
            prop_assert_eq!(frames.len(), 1);
            prop_assert_eq!(frames[0].wasm_offset, Some(hex_off));
            
            // Test decimal offset
            let input = format!("  0: func[1] @ {}", dec_off);
            let frames = extract_frames(&input);
            prop_assert_eq!(frames.len(), 1);
            prop_assert_eq!(frames[0].wasm_offset, Some(dec_off));
        }

        /// Property test: function names with various characters parse correctly
        #[test]
        fn prop_function_name_parsing(func_name: String, module_path: String) {
            // Ensure we have valid strings
            if func_name.is_empty() || module_path.is_empty() {
                return Ok(());
            }
            
            // Test function name alone
            let input = format!("  0: {} @ 0x100", func_name);
            let frames = extract_frames(&input);
            prop_assert_eq!(frames.len(), 1);
            prop_assert_eq!(frames[0].func_name.as_ref(), Some(&func_name));
            
            // Test with module path
            let input = format!("  0: {} @ 0x100", module_path);
            let frames = extract_frames(&input);
            prop_assert_eq!(frames.len(), 1);
            prop_assert_eq!(frames[0].func_name.as_ref(), Some(&module_path));
        }

        /// Property test: trap classification is consistent
        #[test]
        fn prop_trap_classification_is_deterministic(msg: String, msg2: String) {
            let kind1 = classify_trap(&msg);
            let kind2 = classify_trap(&msg);
            prop_assert_eq!(kind1, kind2, "Trap classification should be deterministic");
            
            // Different messages may or may not produce same classification
            let _ = classify_trap(&msg2);
        }

        /// Property test: mixed frame formats in same backtrace
        #[test]
        fn prop_mixed_frame_formats(
            func_idx in 0u32..100u32,
            module_name: String,
            func_name: String,
        ) {
            if module_name.is_empty() || func_name.is_empty() {
                return Ok(());
            }
            
            let input = format!(
                "wasm backtrace:\n  0: func[{}] @ 0x100\n  1: {}::{} @ 0x200\n  2: {}",
                func_idx, module_name, func_name, func_name
            );
            
            let frames = extract_frames(&input);
            
            // We expect at least 2 frames (possibly 3 if bare parsing works)
            prop_assert!(frames.len() >= 2);
            assert_eq!(frames[0].func_index, Some(func_idx));
        }
    }

    /// Test that the regex patterns compile correctly and match expected formats
    #[test]
    fn test_regex_patterns_compile() {
        // Verify lazy patterns compile
        use frame_patterns::*;
        
        // NUMBERED_FRAME should match these
        assert!(NUMBERED_FRAME.is_match("0: func[42] @ 0xa3c"));
        assert!(NUMBERED_FRAME.is_match("#0: func[42] @ 0xa3c"));
        assert!(NUMBERED_FRAME.is_match("1: my_function @ 0x100"));
        assert!(NUMBERED_FRAME.is_match("0: <module>::func"));
        
        // BARE_FRAME should match these
        assert!(BARE_FRAME.is_match("func[42] @ 0xa3c"));
        assert!(BARE_FRAME.is_match("<module>::func @ 0x100"));
        assert!(BARE_FRAME.is_match("my_function"));
        
        // BACKTRACE_HEADER should match these
        assert!(BACKTRACE_HEADER.is_match("wasm backtrace:"));
        assert!(BACKTRACE_HEADER.is_match("backtrace:"));
        assert!(BACKTRACE_HEADER.is_match("WASM TRACE:"));
        assert!(BACKTRACE_HEADER.is_match("  trace:"));
    }

    /// Test that trap patterns compile and match correctly
    #[test]
    fn test_trap_patterns_match() {
        use trap_patterns::*;
        
        // OUT_OF_BOUNDS_MEMORY
        assert!(OUT_OF_BOUNDS_MEMORY.is_match("out of bounds memory access"));
        assert!(OUT_OF_BOUNDS_MEMORY.is_match("Out Of Bounds Memory"));
        assert!(!OUT_OF_BOUNDS_MEMORY.is_match("out of bounds table"));
        
        // INTEGER_OVERFLOW
        assert!(INTEGER_OVERFLOW.is_match("integer overflow"));
        assert!(INTEGER_OVERFLOW.is_match("INTEGER OVERFLOW"));
        assert!(!INTEGER_OVERFLOW.is_match("integer division by zero"));
        
        // DIVISION_BY_ZERO
        assert!(DIVISION_BY_ZERO.is_match("integer division by zero"));
        assert!(DIVISION_BY_ZERO.is_match("division by zero"));
        assert!(DIVISION_BY_ZERO.is_match("Division By Zero"));
        
        // STACK_OVERFLOW
        assert!(STACK_OVERFLOW.is_match("call stack exhausted"));
        assert!(STACK_OVERFLOW.is_match("stack overflow"));
        assert!(STACK_OVERFLOW.is_match("STACK OVERFLOW"));
        
        // HOST_ERROR
        assert!(HOST_ERROR.is_match("HostError: message"));
        assert!(HOST_ERROR.is_match("host error"));
        assert!(HOST_ERROR.is_match("HOSTERROR"));
    }

    /// Test edge cases for frame extraction
    #[test]
    fn test_frame_extraction_edge_cases() {
        // Empty input
        let frames = extract_frames("");
        assert!(frames.is_empty());
        
        // Whitespace only
        let frames = extract_frames("   \n   \n   ");
        assert!(frames.is_empty());
        
        // Non-frame content
        let frames = extract_frames("This is just an error message");
        assert!(frames.is_empty());
        
        // Multiple backtrace headers (should restart)
        let input = "wasm backtrace:\n  0: func[1]\nanother section\nwasm backtrace:\n  0: func[2]";
        let frames = extract_frames(input);
        // Should capture from both sections
        assert!(frames.len() >= 1);
    }

    /// Test classification edge cases
    #[test]
    fn test_classification_edge_cases() {
        // Empty string
        assert!(matches!(classify_trap(""), TrapKind::Unknown(_)));
        
        // Very long string
        let long = "x".repeat(10000);
        let kind = classify_trap(&long);
        assert!(matches!(kind, TrapKind::Unknown(_)));
        
        // Unicode (should be treated as unknown)
        assert!(matches!(classify_trap("你好世界"), TrapKind::Unknown(_)));
    }
}
