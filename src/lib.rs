//! Allocation-free request-time route selection for Breeze HTTP runtimes.
//!
//! A rule is exact when every path segment is literal. A segment beginning
//! with `:` matches one non-empty segment; a terminal `*rest` matches one or
//! more remaining segments. Rules are compiled once and are immutable.

mod index;

pub use index::{
    AllowedMethods, Captures, IndexedRouteRule, PathMode, ResolvedRoute, RouteIndex,
    RouteResolution,
};

use http::Method;

/// One gateway route selected by an HTTP method and absolute path pattern.
#[derive(Clone, Debug)]
pub struct RouteRule {
    /// An empty list selects every HTTP method.
    pub methods: Vec<Method>,
    /// An absolute literal or `:parameter` / terminal `*rest` template path.
    pub path: String,
}

impl RouteRule {
    #[must_use]
    pub fn new(path: impl Into<String>, methods: Vec<Method>) -> Self {
        Self {
            methods,
            path: path.into(),
        }
    }
}

/// A compiled immutable boolean route selector.
#[derive(Clone, Debug, Default)]
pub struct RouteTable(RouteIndex);

impl RouteTable {
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Compiles all rules. This is the only phase that allocates.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-absolute path, an empty parameter name, or
    /// a non-terminal/empty catch-all name.
    pub fn compile(rules: impl IntoIterator<Item = RouteRule>) -> Result<Self, RouteError> {
        RouteIndex::compile(
            rules
                .into_iter()
                .map(|rule| IndexedRouteRule::new(rule.path, rule.methods, 0)),
        )
        .map(Self)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Matches without allocating or locking for ordinary paths of eight
    /// segments or fewer.
    #[must_use]
    #[inline]
    pub fn matches(&self, method: &Method, path: &str) -> bool {
        self.0.matches(method, path)
    }
}

/// A route configuration error.
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("route {index} path must start with '/': {path}")]
    RelativePath { index: usize, path: String },
    #[error("route {index} has an empty parameter segment: {path}")]
    EmptyParameter { index: usize, path: String },
    #[error("route {index} has an invalid catch-all segment: {path}")]
    InvalidCatchAll { index: usize, path: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(methods: &[Method], path: &str) -> RouteRule {
        RouteRule::new(path, methods.to_vec())
    }

    #[test]
    fn exact_length_slots_and_collisions_select_the_right_path() {
        let table = RouteTable::compile([
            rule(&[Method::GET], "/api/a"),
            rule(&[Method::GET], "/api/b"),
            rule(&[Method::POST], "/api/long"),
        ])
        .unwrap();
        assert!(table.matches(&Method::GET, "/api/a"));
        assert!(table.matches(&Method::GET, "/api/b"));
        assert!(!table.matches(&Method::POST, "/api/a"));
        assert!(table.matches(&Method::POST, "/api/long"));
        assert!(!table.matches(&Method::GET, "/api/none"));
    }

    #[test]
    fn templates_walk_literal_and_parameter_branches() {
        let table = RouteTable::compile([
            rule(&[Method::GET], "/api/tasks/:task_id"),
            rule(&[Method::POST], "/api/tasks/new"),
            rule(&[Method::GET], "/api/quota/*path"),
        ])
        .unwrap();
        assert!(table.matches(&Method::GET, "/api/tasks/42"));
        assert!(table.matches(&Method::POST, "/api/tasks/new"));
        assert!(table.matches(&Method::GET, "/api/tasks/new"));
        assert!(!table.matches(&Method::POST, "/api/tasks/42"));
        assert!(table.matches(&Method::GET, "/api/quota/claude/quota"));
        assert!(table.matches(&Method::GET, "/api/quota/"));
        assert!(!table.matches(&Method::GET, "/api/quota"));
    }

    #[test]
    fn root_is_an_exact_path() {
        let table = RouteTable::compile([rule(&[Method::GET], "/")]).unwrap();
        assert!(table.matches(&Method::GET, "/"));
        assert!(!table.matches(&Method::GET, "/api"));
    }

    #[test]
    fn indexed_resolution_returns_priority_captures_and_allowed_methods() {
        let index = RouteIndex::compile([
            IndexedRouteRule::new("/api/:kind/:id", vec![Method::POST], 10),
            IndexedRouteRule::new("/api/users/:id", vec![Method::GET], 20),
        ])
        .unwrap();
        let result = index.resolve("GET", "/api/users/a%2Fb", PathMode::PercentDecoded);
        let selected = result.selected().unwrap();
        assert_eq!(selected.id(), 1);
        assert_eq!(selected.captures().get(0), Some((11, 16)));
        assert_eq!(result.fallback_id(), Some(1));
        assert_eq!(result.allowed_methods().bits() & 0x7f, (1 << 1) | (1 << 5));
    }

    #[test]
    fn deep_paths_use_overflow_without_a_matching_limit() {
        let template = format!("/{}/:id", ["part"; 40].join("/"));
        let path = template.replace(":id", "123");
        let index =
            RouteIndex::compile([IndexedRouteRule::new(template, vec![Method::GET], 1)]).unwrap();
        assert!(index.matches(&Method::GET, &path));
        assert_eq!(
            index
                .resolve("GET", &path, PathMode::Raw)
                .selected()
                .unwrap()
                .captures()
                .get(0),
            Some((path.len() - 3, path.len()))
        );
    }

    #[test]
    fn encoded_literals_are_optional() {
        let index = RouteIndex::compile([IndexedRouteRule::new("/users/中", vec![Method::GET], 1)])
            .unwrap();
        assert!(
            index
                .resolve("GET", "/users/%E4%B8%AD", PathMode::Raw)
                .selected()
                .is_none()
        );
        assert!(
            index
                .resolve("GET", "/users/%E4%B8%AD", PathMode::PercentDecoded)
                .selected()
                .is_some()
        );
    }

    #[test]
    fn higher_priority_pattern_can_override_an_exact_path() {
        let index = RouteIndex::compile([
            IndexedRouteRule::new("/api/:name", vec![Method::GET], 20),
            IndexedRouteRule::new("/api/users", vec![Method::GET], 10),
        ])
        .unwrap();
        assert_eq!(
            index
                .resolve("GET", "/api/users", PathMode::Raw)
                .selected()
                .unwrap()
                .id(),
            0
        );

        let index = RouteIndex::compile([
            IndexedRouteRule::new("/api/:name", vec![Method::GET], 10),
            IndexedRouteRule::new("/api/users", vec![Method::GET], 20),
        ])
        .unwrap();
        assert_eq!(
            index
                .resolve("GET", "/api/users", PathMode::Raw)
                .selected()
                .unwrap()
                .id(),
            1
        );
    }
}
