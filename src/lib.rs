//! Allocation-free request-time route selection for Breeze gateways.
//!
//! A rule is exact when every path segment is literal. A segment beginning
//! with `:` matches one non-empty segment; a terminal `*name` matches one or
//! more remaining segments. Rules are compiled once and are immutable.

use std::collections::HashMap;
use std::sync::Arc;

use http::Method;

/// One route selected by an HTTP method and absolute path pattern.
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

/// A compiled immutable route selector.
#[derive(Clone, Debug, Default)]
pub struct RouteTable {
    exact: ExactRoutes,
    patterns: Arc<PatternIndex>,
    len: usize,
}

impl RouteTable {
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Compiles all rules. This is the only phase that allocates.
    ///
    /// Exact paths are grouped by byte length. A unique length slot performs
    /// no hash lookup at request time; only paths sharing one byte length use
    /// the collision map. Parameter and catch-all routes are inserted into a
    /// segment trie.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-absolute path, an empty parameter name, or
    /// a non-terminal/empty catch-all name.
    pub fn compile(rules: impl IntoIterator<Item = RouteRule>) -> Result<Self, RouteError> {
        let mut exact: HashMap<Box<str>, MethodSet> = HashMap::new();
        let mut patterns = Vec::new();
        let mut len = 0;
        for (index, rule) in rules.into_iter().enumerate() {
            if !rule.path.starts_with('/') {
                return Err(RouteError::RelativePath {
                    index,
                    path: rule.path,
                });
            }
            let methods = MethodSet::new(rule.methods);
            if is_pattern(&rule.path) {
                patterns.push(RawPattern {
                    index,
                    path: rule.path,
                    methods,
                });
            } else {
                match exact.entry(rule.path.into_boxed_str()) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().merge(methods);
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(methods);
                    }
                }
            }
            len += 1;
        }
        Ok(Self {
            exact: ExactRoutes::compile(exact.into_iter().collect()),
            patterns: Arc::new(PatternIndex::compile(patterns)?),
            len,
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Matches without allocating, locking, or decoding the request path.
    #[must_use]
    pub fn matches(&self, method: &Method, path: &str) -> bool {
        self.exact.matches(method, path) || self.patterns.matches(method, path)
    }
}

fn is_pattern(path: &str) -> bool {
    path.split('/')
        .skip(1)
        .any(|segment| matches!(segment.as_bytes().first(), Some(b':' | b'*')))
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

#[derive(Clone, Debug, Default)]
struct ExactRoutes {
    by_length: Arc<[ExactLengthSlot]>,
    collisions: Arc<HashMap<Box<str>, MethodSet>>,
}

impl ExactRoutes {
    fn compile(routes: Vec<(Box<str>, MethodSet)>) -> Self {
        let Some(max_length) = routes.iter().map(|(path, _)| path.len()).max() else {
            return Self::default();
        };
        let mut buckets = (0..=max_length).map(|_| Vec::new()).collect::<Vec<_>>();
        for route in routes {
            buckets[route.0.len()].push(route);
        }

        let mut by_length = Vec::with_capacity(buckets.len());
        let mut collisions = HashMap::new();
        for bucket in buckets {
            match bucket.len() {
                0 => by_length.push(ExactLengthSlot::Empty),
                1 => {
                    let (path, methods) = bucket.into_iter().next().expect("one route in bucket");
                    by_length.push(ExactLengthSlot::Direct(ExactRoute { path, methods }));
                }
                _ => {
                    by_length.push(ExactLengthSlot::Collision);
                    collisions.extend(bucket);
                }
            }
        }
        Self {
            by_length: by_length.into(),
            collisions: Arc::new(collisions),
        }
    }

    fn matches(&self, method: &Method, path: &str) -> bool {
        match self.by_length.get(path.len()) {
            Some(ExactLengthSlot::Direct(route)) => {
                route.path.as_ref() == path && route.methods.matches(method)
            }
            Some(ExactLengthSlot::Collision) => self
                .collisions
                .get(path)
                .is_some_and(|methods| methods.matches(method)),
            Some(ExactLengthSlot::Empty) | None => false,
        }
    }
}

#[derive(Clone, Debug, Default)]
enum ExactLengthSlot {
    #[default]
    Empty,
    Direct(ExactRoute),
    Collision,
}

#[derive(Clone, Debug)]
struct ExactRoute {
    path: Box<str>,
    methods: MethodSet,
}

/// Common methods use a bitmask. Extension methods remain supported without a
/// request-time allocation or hash calculation.
#[derive(Clone, Debug, Default)]
struct MethodSet {
    any: bool,
    standard: u16,
    extensions: Box<[Method]>,
}

impl MethodSet {
    fn new(methods: Vec<Method>) -> Self {
        if methods.is_empty() {
            return Self {
                any: true,
                ..Self::default()
            };
        }
        let mut result = Self::default();
        for method in methods {
            result.insert(method);
        }
        result
    }

    fn merge(&mut self, other: Self) {
        if self.any || other.any {
            *self = Self {
                any: true,
                ..Self::default()
            };
            return;
        }
        self.standard |= other.standard;
        if other.extensions.is_empty() {
            return;
        }
        let mut extensions = self.extensions.to_vec();
        for method in other.extensions.into_vec() {
            if !extensions.contains(&method) {
                extensions.push(method);
            }
        }
        self.extensions = extensions.into();
    }

    fn insert(&mut self, method: Method) {
        if let Some(bit) = method_bit(&method) {
            self.standard |= bit;
            return;
        }
        let mut extensions = self.extensions.to_vec();
        if !extensions.contains(&method) {
            extensions.push(method);
        }
        self.extensions = extensions.into();
    }

    fn matches(&self, method: &Method) -> bool {
        self.any
            || method_bit(method).is_some_and(|bit| self.standard & bit != 0)
            || self.extensions.contains(method)
    }
}

fn method_bit(method: &Method) -> Option<u16> {
    Some(match method.as_str() {
        "CONNECT" => 1 << 0,
        "DELETE" => 1 << 1,
        "GET" => 1 << 2,
        "HEAD" => 1 << 3,
        "OPTIONS" => 1 << 4,
        "PATCH" => 1 << 5,
        "POST" => 1 << 6,
        "PUT" => 1 << 7,
        "TRACE" => 1 << 8,
        _ => return None,
    })
}

struct RawPattern {
    index: usize,
    path: String,
    methods: MethodSet,
}

#[derive(Clone, Debug, Default)]
struct PatternIndex {
    /// A direct array indexed by the number of request path segments.
    fixed: Arc<[Option<TemplateBucket>]>,
    /// Catch-all templates are grouped by their required minimum segment count.
    rest: Arc<[Option<TemplateBucket>]>,
}

impl PatternIndex {
    fn compile(routes: Vec<RawPattern>) -> Result<Self, RouteError> {
        let mut fixed = Vec::<Vec<TemplateRoute>>::new();
        let mut rest = Vec::<Vec<TemplateRoute>>::new();
        for route in routes {
            let parsed = TemplateRoute::parse(route)?;
            let buckets = if parsed.rest { &mut rest } else { &mut fixed };
            if buckets.len() <= parsed.minimum_segments {
                buckets.resize_with(parsed.minimum_segments + 1, Vec::new);
            }
            buckets[parsed.minimum_segments].push(parsed);
        }
        Ok(Self {
            fixed: buckets_into_index(fixed),
            rest: buckets_into_index(rest),
        })
    }

    fn matches(&self, method: &Method, path: &str) -> bool {
        let Some(segments) = RequestSegments::parse(path) else {
            return false;
        };
        if self
            .fixed
            .get(segments.len)
            .and_then(Option::as_ref)
            .is_some_and(|bucket| bucket.matches(method, &segments))
        {
            return true;
        }
        if self.rest.is_empty() {
            return false;
        }
        let maximum = segments.len.min(self.rest.len() - 1);
        self.rest[..=maximum]
            .iter()
            .flatten()
            .any(|bucket| bucket.matches(method, &segments))
    }
}

fn buckets_into_index(buckets: Vec<Vec<TemplateRoute>>) -> Arc<[Option<TemplateBucket>]> {
    buckets
        .into_iter()
        .map(|routes| (!routes.is_empty()).then(|| TemplateBucket::compile(routes)))
        .collect::<Vec<_>>()
        .into()
}

#[derive(Clone, Debug)]
struct TemplateRoute {
    methods: MethodSet,
    segments: Box<[TemplateSegment]>,
    minimum_segments: usize,
    rest: bool,
}

#[derive(Clone, Debug)]
enum TemplateSegment {
    Literal(Box<str>),
    Parameter,
}

impl TemplateRoute {
    fn parse(route: RawPattern) -> Result<Self, RouteError> {
        let segment_count = route.path.split('/').count() - 1;
        let mut segments = Vec::with_capacity(segment_count);
        let mut rest = false;
        for (position, segment) in route.path.split('/').skip(1).enumerate() {
            if let Some(name) = segment.strip_prefix(':') {
                if name.is_empty() {
                    return Err(RouteError::EmptyParameter {
                        index: route.index,
                        path: route.path,
                    });
                }
                segments.push(TemplateSegment::Parameter);
            } else if let Some(name) = segment.strip_prefix('*') {
                if name.is_empty() || position + 1 != segment_count {
                    return Err(RouteError::InvalidCatchAll {
                        index: route.index,
                        path: route.path,
                    });
                }
                rest = true;
                break;
            } else {
                segments.push(TemplateSegment::Literal(segment.into()));
            }
        }
        Ok(Self {
            methods: route.methods,
            segments: segments.into(),
            minimum_segments: segment_count,
            rest,
        })
    }

    fn matches(&self, method: &Method, actual: &RequestSegments<'_>) -> bool {
        if !self.methods.matches(method) || actual.len < self.minimum_segments {
            return false;
        }
        for (position, expected) in self.segments.iter().enumerate() {
            let Some(actual) = actual.get(position) else {
                return false;
            };
            if match expected {
                TemplateSegment::Literal(expected) => actual != expected.as_ref(),
                TemplateSegment::Parameter => actual.is_empty(),
            } {
                return false;
            }
        }
        true
    }
}

/// One segment-count bucket. At compile time choose the literal position that
/// leaves the fewest worst-case candidates, mirroring the selective literal
/// buckets in `brz-http-server`'s route index.
#[derive(Clone, Debug)]
struct TemplateBucket {
    routes: Arc<[TemplateRoute]>,
    selector: Option<LiteralSelector>,
}

#[derive(Clone, Debug)]
struct LiteralSelector {
    position: usize,
    literals: HashMap<Box<str>, Box<[usize]>>,
    parameters: Box<[usize]>,
}

impl TemplateBucket {
    fn compile(routes: Vec<TemplateRoute>) -> Self {
        let selector = select_literal(&routes);
        Self {
            routes: routes.into(),
            selector,
        }
    }

    fn matches(&self, method: &Method, actual: &RequestSegments<'_>) -> bool {
        let Some(selector) = &self.selector else {
            return self
                .routes
                .iter()
                .any(|route| route.matches(method, actual));
        };
        let segment = actual
            .get(selector.position)
            .expect("selector position is below the bucket minimum");
        selector
            .literals
            .get(segment)
            .into_iter()
            .flatten()
            .chain(selector.parameters.iter())
            .any(|&index| self.routes[index].matches(method, actual))
    }
}

fn select_literal(routes: &[TemplateRoute]) -> Option<LiteralSelector> {
    let width = routes.first()?.segments.len();
    let mut selected = None;
    for position in 0..width {
        let mut literals = HashMap::<Box<str>, Vec<usize>>::new();
        let mut parameters = Vec::new();
        for (index, route) in routes.iter().enumerate() {
            match &route.segments[position] {
                TemplateSegment::Literal(literal) => {
                    literals.entry(literal.clone()).or_default().push(index);
                }
                TemplateSegment::Parameter => parameters.push(index),
            }
        }
        let maximum = literals.values().map(Vec::len).max().unwrap_or(0) + parameters.len();
        if literals.is_empty() || maximum >= routes.len() {
            continue;
        }
        if selected
            .as_ref()
            .is_some_and(|(_, best, _)| maximum >= *best)
        {
            continue;
        }
        selected = Some((position, maximum, (literals, parameters)));
    }
    selected.map(|(position, _, (literals, parameters))| LiteralSelector {
        position,
        literals: literals
            .into_iter()
            .map(|(literal, indices)| (literal, indices.into()))
            .collect(),
        parameters: parameters.into(),
    })
}

/// A fixed-size borrowed segment view. More segments are counted but only the
/// first 32 are retained; Wegent's configured templates have fewer fixed
/// segments, so request matching stays allocation-free even for catch-all URLs.
struct RequestSegments<'a> {
    path: &'a str,
    ranges: [(usize, usize); 32],
    stored: usize,
    len: usize,
}

impl<'a> RequestSegments<'a> {
    fn parse(path: &'a str) -> Option<Self> {
        let remainder = path.strip_prefix('/')?;
        let mut result = Self {
            path,
            ranges: [(0, 0); 32],
            stored: 0,
            len: 0,
        };
        let mut start = path.len() - remainder.len();
        for (offset, byte) in remainder.bytes().enumerate() {
            if byte == b'/' {
                result.push((start, start + offset));
                start += offset + 1;
                let rest = &remainder[offset + 1..];
                return Self::parse_tail(result, start, rest);
            }
        }
        result.push((start, path.len()));
        Some(result)
    }

    fn parse_tail(mut result: Self, mut start: usize, mut remainder: &'a str) -> Option<Self> {
        loop {
            let Some((segment, rest)) = remainder.split_once('/') else {
                result.push((start, start + remainder.len()));
                return Some(result);
            };
            result.push((start, start + segment.len()));
            start += segment.len() + 1;
            remainder = rest;
        }
    }

    fn push(&mut self, range: (usize, usize)) {
        if self.stored < self.ranges.len() {
            self.ranges[self.stored] = range;
            self.stored += 1;
        }
        self.len += 1;
    }

    fn get(&self, index: usize) -> Option<&'a str> {
        (index < self.stored).then(|| {
            let (start, end) = self.ranges[index];
            &self.path[start..end]
        })
    }
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
}
