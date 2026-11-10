//! Shared pieces of the tool implementations: argument access, schema builders, errors.

use serde_json::{Map, Value, json};

use crate::backend::{ApiError, ErrorKind};
use crate::safety::Refusal;

/// How a tool call failed. Shown to the model as a tool execution error, which models can
/// read and fix; protocol errors are reserved for malformed requests.
#[derive(Debug, Clone)]
pub struct ToolError {
    pub kind: FailKind,
    pub message: String,
    pub detail: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailKind {
    /// The arguments are wrong.
    Invalid,
    /// The safety model said no.
    Refused,
    /// A backend rejected or could not serve the request.
    Backend,
    /// The needed backend or feature is not configured.
    NotConfigured,
    /// The optional LLM failed or its answer was rejected.
    Llm,
    /// The server failed.
    Internal,
}

impl FailKind {
    pub const fn name(self) -> &'static str {
        match self {
            FailKind::Invalid => "invalid_arguments",
            FailKind::Refused => "refused",
            FailKind::Backend => "backend_error",
            FailKind::NotConfigured => "not_configured",
            FailKind::Llm => "llm_error",
            FailKind::Internal => "internal_error",
        }
    }
}

impl ToolError {
    pub fn new(kind: FailKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            detail: None,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(FailKind::Invalid, message)
    }

    pub fn not_configured(message: impl Into<String>) -> Self {
        Self::new(FailKind::NotConfigured, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(FailKind::Internal, message)
    }

    #[must_use]
    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn to_value(&self) -> Value {
        let mut error = json!({"kind": self.kind.name(), "message": self.message});
        if let Some(detail) = &self.detail {
            error["detail"] = detail.clone();
        }
        json!({ "error": error })
    }
}

impl From<ApiError> for ToolError {
    fn from(error: ApiError) -> Self {
        let hint = match error.kind {
            ErrorKind::Auth => " (the credential this server was configured with was rejected)",
            ErrorKind::Transport => " (is the backend running and the URL right?)",
            _ => "",
        };
        let detail = error.to_value();
        Self {
            kind: FailKind::Backend,
            message: format!("{error}{hint}"),
            detail: Some(detail),
        }
    }
}

impl From<Refusal> for ToolError {
    fn from(refusal: Refusal) -> Self {
        Self::new(FailKind::Refused, refusal.0)
    }
}

pub type ToolResult = Result<Value, ToolError>;

/// Typed access to validated arguments.
#[derive(Debug, Clone, Default)]
pub struct Args(pub Map<String, Value>);

impl Args {
    pub fn from_value(value: Value) -> Self {
        match value {
            Value::Object(map) => Self(map),
            _ => Self::default(),
        }
    }

    pub fn str(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(Value::as_str)
    }

    pub fn string(&self, key: &str) -> Option<String> {
        self.str(key).map(str::to_owned)
    }

    pub fn u64(&self, key: &str) -> Option<u64> {
        self.0.get(key).and_then(Value::as_u64)
    }

    pub fn bool(&self, key: &str) -> Option<bool> {
        self.0.get(key).and_then(Value::as_bool)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    pub fn require_str(&self, key: &str) -> Result<&str, ToolError> {
        self.str(key)
            .ok_or_else(|| ToolError::invalid(format!("`{key}` is required")))
    }

    pub fn dry_run(&self) -> bool {
        self.bool("dry_run").unwrap_or(false)
    }
}

// --- schema builders -------------------------------------------------------------------------

/// An object schema that rejects unknown properties.
pub fn object(properties: Vec<(&str, Value)>, required: &[&str]) -> Value {
    let mut props = Map::new();
    for (name, schema) in properties {
        props.insert(name.to_owned(), schema);
    }
    json!({
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": false,
    })
}

/// A free-form object (any members).
pub fn free_object(description: &str) -> Value {
    json!({"type": "object", "description": description})
}

pub fn string(description: &str) -> Value {
    json!({"type": "string", "description": description})
}

pub fn string_max(description: &str, max: u64) -> Value {
    json!({"type": "string", "description": description, "minLength": 1, "maxLength": max})
}

pub fn pattern(description: &str, pattern: &str) -> Value {
    json!({"type": "string", "description": description, "pattern": pattern})
}

pub fn integer(description: &str, min: i64, max: i64) -> Value {
    json!({"type": "integer", "description": description, "minimum": min, "maximum": max})
}

pub fn boolean(description: &str) -> Value {
    json!({"type": "boolean", "description": description})
}

pub fn choice(description: &str, values: &[&str]) -> Value {
    json!({"type": "string", "description": description, "enum": values})
}

pub fn array(description: &str, items: Value, max_items: u64) -> Value {
    json!({"type": "array", "description": description, "items": items, "maxItems": max_items})
}

/// The org argument every org-scoped tool takes.
pub fn org_arg() -> Value {
    pattern(
        "Org id ([a-z0-9_-], 1 to 64). Defaults to the org of the configured control-plane key.",
        "^[a-z0-9_-]{1,64}$",
    )
}

/// The `dry_run` argument every mutating tool takes.
pub fn dry_run_arg() -> Value {
    boolean("Validate and show what would change, without changing anything.")
}

/// The longest prefix of `text` that is at most `max` bytes and ends on a character boundary,
/// and whether anything was cut.
pub fn clip(text: &str, max: usize) -> (&str, bool) {
    if text.len() <= max {
        return (text, false);
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

/// A UUID path segment check shared by the session and block tools.
pub fn is_uuid(text: &str) -> bool {
    crate::schema::is_uuid(text)
}

/// Current Unix time in seconds.
pub fn now() -> i64 {
    crate::store::now_secs()
}
