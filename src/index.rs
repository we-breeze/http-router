use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

use http::Method;

use crate::RouteError;

const INLINE_SEGMENTS: usize = 8;
const INLINE_CAPTURES: usize = 8;
const STANDARD_METHODS: u16 = (1 << 9) - 1;

/// Controls how literal path segments are compared.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PathMode {
    /// Compare the request path exactly as received.
    #[default]
    Raw,
    /// Split on raw `/` bytes, then percent-decode each segment for comparison.
    PercentDecoded,
}

/// One route compiled into an [`RouteIndex`]. Its position is its stable route id.
#[derive(Clone, Debug)]
pub struct IndexedRouteRule {
    pub path: String,
    pub methods: Vec<Method>,
    pub priority: usize,
}

impl IndexedRouteRule {
    #[must_use]
    pub fn new(path: impl Into<String>, methods: Vec<Method>, priority: usize) -> Self {
        Self {
            path: path.into(),
            methods,
            priority,
        }
    }
}

/// The standard methods whose matching routes were found for a request path.
///
/// Bits 0 through 8 are DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT,
/// CONNECT, and TRACE respectively.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllowedMethods(u16);

impl AllowedMethods {
    #[must_use]
    pub fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub fn contains(self, method: &Method) -> bool {
        method_bit(method.as_str()).is_some_and(|bit| self.0 & bit != 0)
    }
}

/// Raw byte ranges for captures of the selected route.
#[derive(Clone, Copy, Debug)]
pub struct Captures {
    ranges: [PathRange; INLINE_CAPTURES],
    len: usize,
}

impl Default for Captures {
    fn default() -> Self {
        Self {
            ranges: [PathRange::default(); INLINE_CAPTURES],
            len: 0,
        }
    }
}

impl Captures {
    fn push(&mut self, range: PathRange) {
        if let Some(slot) = self.ranges.get_mut(self.len) {
            *slot = range;
        }
        self.len += 1;
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns one of the first eight capture ranges.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<(usize, usize)> {
        (index < self.len.min(self.ranges.len())).then(|| self.ranges[index].bounds())
    }
}

/// The selected route id and its raw capture ranges.
#[derive(Clone, Copy, Debug)]
pub struct ResolvedRoute {
    id: usize,
    captures: Captures,
}

impl ResolvedRoute {
    #[must_use]
    pub fn id(self) -> usize {
        self.id
    }

    #[must_use]
    pub fn captures(&self) -> &Captures {
        &self.captures
    }
}

/// One routing decision. The fallback id is the highest-priority path match,
/// even when its methods do not include the requested method.
#[derive(Clone, Copy, Debug, Default)]
pub struct RouteResolution {
    selected: Option<ResolvedRoute>,
    fallback: Option<usize>,
    fallback_priority: usize,
    allowed: AllowedMethods,
}

impl RouteResolution {
    #[must_use]
    pub fn selected(&self) -> Option<&ResolvedRoute> {
        self.selected.as_ref()
    }

    #[must_use]
    pub fn fallback_id(&self) -> Option<usize> {
        self.fallback
    }

    #[must_use]
    pub fn allowed_methods(&self) -> AllowedMethods {
        self.allowed
    }
}

fn better(priority: usize, id: usize, current_priority: usize, current: Option<usize>) -> bool {
    current.is_none()
        || priority > current_priority
        || (priority == current_priority && current.is_some_and(|current| id < current))
}

/// Immutable shared path index used by the gateway and HTTP server.
#[derive(Clone, Debug, Default)]
pub struct RouteIndex {
    entries: Arc<[RouteEntry]>,
    exact: ExactRoutes,
    patterns: PatternIndex,
    decoded: PatternIndex,
    best_pattern: Option<(usize, usize)>,
}

impl RouteIndex {
    /// Compiles route paths once. Request-time resolution does not allocate for
    /// paths of eight segments or fewer.
    pub fn compile(rules: impl IntoIterator<Item = IndexedRouteRule>) -> Result<Self, RouteError> {
        let mut entries = Vec::new();
        for (index, rule) in rules.into_iter().enumerate() {
            entries.push(RouteEntry::parse(index, rule)?);
        }
        let exact_ids = entries
            .iter()
            .enumerate()
            .filter_map(|(id, entry)| (!entry.pattern).then_some(id))
            .collect::<Vec<_>>();
        let pattern_ids = entries
            .iter()
            .enumerate()
            .filter_map(|(id, entry)| entry.pattern.then_some(id))
            .collect::<Vec<_>>();
        let best_pattern = pattern_ids.iter().copied().reduce(|current, candidate| {
            if better(
                entries[candidate].priority,
                candidate,
                entries[current].priority,
                Some(current),
            ) {
                candidate
            } else {
                current
            }
        });
        let all_ids = (0..entries.len()).collect::<Vec<_>>();
        Ok(Self {
            exact: ExactRoutes::compile(&entries, exact_ids),
            patterns: PatternIndex::compile(&entries, pattern_ids),
            decoded: PatternIndex::compile(&entries, all_ids),
            best_pattern: best_pattern.map(|id| (entries[id].priority, id)),
            entries: entries.into(),
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    #[inline]
    pub fn matches(&self, method: &Method, path: &str) -> bool {
        self.matches_str(method.as_str(), path)
    }

    #[must_use]
    #[inline]
    pub fn matches_str(&self, method: &str, path: &str) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        if self.exact.ids(path).is_some_and(|ids| {
            ids.iter()
                .any(|&id| self.entries[id].methods.matches_str(method))
        }) {
            return true;
        }
        let Some(segments) = RequestSegments::parse(path) else {
            return false;
        };
        self.patterns
            .any_match(&segments, &self.entries, PathMode::Raw, |entry| {
                entry.methods.matches_str(method)
            })
    }

    #[must_use]
    #[inline]
    pub fn resolve(&self, method: &str, path: &str, mode: PathMode) -> RouteResolution {
        self.resolve_inner(method, path, mode, false)
    }

    /// Resolves with a terminal catch-all also matching a path with no slash
    /// or segment after its fixed prefix. This preserves the HTTP server's
    /// established `/*rest` behavior.
    #[must_use]
    #[inline]
    pub fn resolve_allowing_empty_catch_all(
        &self,
        method: &str,
        path: &str,
        mode: PathMode,
    ) -> RouteResolution {
        self.resolve_inner(method, path, mode, true)
    }

    #[inline]
    fn resolve_inner(
        &self,
        method: &str,
        path: &str,
        mode: PathMode,
        allow_empty_catch_all: bool,
    ) -> RouteResolution {
        let mut result = RouteResolution::default();
        let mut selected_priority = 0;
        if self.entries.is_empty() {
            return result;
        }
        if mode == PathMode::Raw {
            if let Some(ids) = self.exact.ids(path) {
                for &id in ids {
                    consider(
                        &mut result,
                        &mut selected_priority,
                        id,
                        &self.entries[id],
                        Captures::default(),
                        method,
                    );
                }
                if let Some(selected) = result.selected {
                    let no_pattern_can_win = self.best_pattern.is_none_or(|(priority, id)| {
                        !better(priority, id, selected_priority, Some(selected.id))
                    });
                    if no_pattern_can_win {
                        return result;
                    }
                }
            }
        }
        let Some(segments) = RequestSegments::parse(path) else {
            return result;
        };
        let index = if mode == PathMode::Raw {
            &self.patterns
        } else {
            &self.decoded
        };
        index.visit_matches(
            &segments,
            &self.entries,
            mode,
            allow_empty_catch_all,
            |id, captures| {
                consider(
                    &mut result,
                    &mut selected_priority,
                    id,
                    &self.entries[id],
                    captures,
                    method,
                );
            },
        );
        result
    }
}

#[inline]
fn consider(
    result: &mut RouteResolution,
    selected_priority: &mut usize,
    id: usize,
    entry: &RouteEntry,
    captures: Captures,
    method: &str,
) {
    result.allowed.0 |= entry.methods.standard_bits();
    if better(
        entry.priority,
        id,
        result.fallback_priority,
        result.fallback,
    ) {
        result.fallback = Some(id);
        result.fallback_priority = entry.priority;
    }
    if entry.methods.matches_str(method)
        && better(
            entry.priority,
            id,
            *selected_priority,
            result.selected.map(|selected| selected.id),
        )
    {
        result.selected = Some(ResolvedRoute { id, captures });
        *selected_priority = entry.priority;
    }
}

#[derive(Clone, Debug)]
struct RouteEntry {
    path: Box<str>,
    methods: MethodSet,
    priority: usize,
    segments: Box<[TemplateSegment]>,
    minimum_segments: usize,
    rest: bool,
    pattern: bool,
}

impl RouteEntry {
    fn parse(index: usize, rule: IndexedRouteRule) -> Result<Self, RouteError> {
        if !rule.path.starts_with('/') {
            return Err(RouteError::RelativePath {
                index,
                path: rule.path,
            });
        }
        let minimum_segments = rule.path.split('/').count() - 1;
        let mut segments = Vec::with_capacity(minimum_segments);
        let mut rest = false;
        let mut pattern = false;
        for (position, segment) in rule.path.split('/').skip(1).enumerate() {
            if let Some(name) = segment.strip_prefix(':') {
                if name.is_empty() {
                    return Err(RouteError::EmptyParameter {
                        index,
                        path: rule.path,
                    });
                }
                pattern = true;
                segments.push(TemplateSegment::Parameter);
            } else if let Some(name) = segment.strip_prefix('*') {
                if name.is_empty() || position + 1 != minimum_segments {
                    return Err(RouteError::InvalidCatchAll {
                        index,
                        path: rule.path,
                    });
                }
                pattern = true;
                rest = true;
                break;
            } else {
                segments.push(TemplateSegment::Literal(segment.into()));
            }
        }
        Ok(Self {
            path: rule.path.into_boxed_str(),
            methods: MethodSet::new(rule.methods),
            priority: rule.priority,
            segments: segments.into(),
            minimum_segments,
            rest,
            pattern,
        })
    }

    fn key(&self, id: usize) -> (Reverse<usize>, usize) {
        (Reverse(self.priority), id)
    }

    #[inline]
    fn matches(
        &self,
        actual: &RequestSegments<'_>,
        mode: PathMode,
        allow_empty_catch_all: bool,
    ) -> Option<Captures> {
        if if self.rest {
            actual.len + usize::from(allow_empty_catch_all) < self.minimum_segments
        } else {
            actual.len != self.minimum_segments
        } {
            return None;
        }
        let mut captures = Captures::default();
        for (position, expected) in self.segments.iter().enumerate() {
            let range = actual.get(position)?;
            let (start, end) = range.bounds();
            let value = &actual.path[start..end];
            match expected {
                TemplateSegment::Literal(expected) => {
                    if !literal_matches(value, expected, mode) {
                        return None;
                    }
                }
                TemplateSegment::Parameter => {
                    if value.is_empty() {
                        return None;
                    }
                    captures.push(range);
                }
            }
        }
        if self.rest {
            let start = actual
                .get(self.segments.len())
                .map_or(actual.path.len(), |range| range.start());
            captures.push(PathRange::new(start, actual.path.len())?);
        }
        Some(captures)
    }
}

#[derive(Clone, Debug)]
enum TemplateSegment {
    Literal(Box<str>),
    Parameter,
}

#[inline]
fn literal_matches(actual: &str, expected: &str, mode: PathMode) -> bool {
    if mode == PathMode::PercentDecoded && actual.as_bytes().contains(&b'%') {
        percent_encoding::percent_decode_str(actual).decode_utf8_lossy() == expected
    } else {
        actual == expected
    }
}

#[derive(Clone, Debug, Default)]
struct ExactRoutes {
    by_length: Arc<[ExactLengthSlot]>,
    collisions: Arc<HashMap<Box<str>, Box<[usize]>>>,
}

impl ExactRoutes {
    fn compile(entries: &[RouteEntry], ids: Vec<usize>) -> Self {
        let mut paths = HashMap::<Box<str>, Vec<usize>>::new();
        for id in ids {
            paths.entry(entries[id].path.clone()).or_default().push(id);
        }
        let Some(max_length) = paths.keys().map(|path| path.len()).max() else {
            return Self::default();
        };
        let mut buckets = (0..=max_length).map(|_| Vec::new()).collect::<Vec<_>>();
        for route in paths {
            buckets[route.0.len()].push(route);
        }
        let mut by_length = Vec::with_capacity(buckets.len());
        let mut collisions = HashMap::new();
        for bucket in buckets {
            match bucket.len() {
                0 => by_length.push(ExactLengthSlot::Empty),
                1 => {
                    let (path, ids) = bucket.into_iter().next().expect("one route in bucket");
                    by_length.push(ExactLengthSlot::Direct(ExactPath {
                        path,
                        ids: ids.into(),
                    }));
                }
                _ => {
                    by_length.push(ExactLengthSlot::Collision);
                    collisions.extend(
                        bucket
                            .into_iter()
                            .map(|(path, ids)| (path, ids.into_boxed_slice())),
                    );
                }
            }
        }
        Self {
            by_length: by_length.into(),
            collisions: Arc::new(collisions),
        }
    }

    #[inline]
    fn ids(&self, path: &str) -> Option<&[usize]> {
        match self.by_length.get(path.len()) {
            Some(ExactLengthSlot::Direct(route)) if route.path.as_ref() == path => Some(&route.ids),
            Some(ExactLengthSlot::Collision) => self.collisions.get(path).map(AsRef::as_ref),
            Some(ExactLengthSlot::Empty | ExactLengthSlot::Direct(_)) | None => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
enum ExactLengthSlot {
    #[default]
    Empty,
    Direct(ExactPath),
    Collision,
}

#[derive(Clone, Debug)]
struct ExactPath {
    path: Box<str>,
    ids: Box<[usize]>,
}

#[derive(Clone, Debug, Default)]
struct PatternIndex {
    fixed: Arc<[Option<TemplateBucket>]>,
    rest: Arc<[Option<TemplateBucket>]>,
}

impl PatternIndex {
    fn compile(entries: &[RouteEntry], ids: Vec<usize>) -> Self {
        let mut fixed = Vec::<Vec<usize>>::new();
        let mut rest = Vec::<Vec<usize>>::new();
        for id in ids {
            let entry = &entries[id];
            let buckets = if entry.rest { &mut rest } else { &mut fixed };
            if buckets.len() <= entry.minimum_segments {
                buckets.resize_with(entry.minimum_segments + 1, Vec::new);
            }
            buckets[entry.minimum_segments].push(id);
        }
        Self {
            fixed: buckets_into_index(entries, fixed),
            rest: buckets_into_index(entries, rest),
        }
    }

    #[inline]
    fn visit_matches(
        &self,
        actual: &RequestSegments<'_>,
        entries: &[RouteEntry],
        mode: PathMode,
        allow_empty_catch_all: bool,
        mut visit: impl FnMut(usize, Captures),
    ) {
        if let Some(bucket) = self.fixed.get(actual.len).and_then(Option::as_ref) {
            bucket.visit_candidates(actual, mode, |id| {
                if let Some(captures) = entries[id].matches(actual, mode, allow_empty_catch_all) {
                    visit(id, captures);
                }
            });
        }
        if self.rest.is_empty() {
            return;
        }
        let maximum = (actual.len + usize::from(allow_empty_catch_all)).min(self.rest.len() - 1);
        for bucket in self.rest[..=maximum].iter().flatten() {
            bucket.visit_candidates(actual, mode, |id| {
                if let Some(captures) = entries[id].matches(actual, mode, allow_empty_catch_all) {
                    visit(id, captures);
                }
            });
        }
    }

    fn any_match(
        &self,
        actual: &RequestSegments<'_>,
        entries: &[RouteEntry],
        mode: PathMode,
        accept: impl Fn(&RouteEntry) -> bool + Copy,
    ) -> bool {
        let mut found = false;
        self.visit_matches(actual, entries, mode, false, |id, _| {
            found |= accept(&entries[id]);
        });
        found
    }
}

fn buckets_into_index(
    entries: &[RouteEntry],
    buckets: Vec<Vec<usize>>,
) -> Arc<[Option<TemplateBucket>]> {
    buckets
        .into_iter()
        .map(|ids| (!ids.is_empty()).then(|| TemplateBucket::compile(entries, ids)))
        .collect::<Vec<_>>()
        .into()
}

#[derive(Clone, Debug)]
struct TemplateBucket {
    routes: Box<[usize]>,
    selector: Option<LiteralSelector>,
}

#[derive(Clone, Debug)]
struct LiteralSelector {
    position: usize,
    literals: HashMap<Box<str>, Box<[usize]>>,
    parameters: Box<[usize]>,
}

impl TemplateBucket {
    fn compile(entries: &[RouteEntry], mut routes: Vec<usize>) -> Self {
        routes.sort_by_key(|&id| entries[id].key(id));
        let selector = select_literal(entries, &routes);
        Self {
            routes: routes.into(),
            selector,
        }
    }

    #[inline]
    fn visit_candidates(
        &self,
        actual: &RequestSegments<'_>,
        mode: PathMode,
        mut visit: impl FnMut(usize),
    ) {
        let Some(selector) = &self.selector else {
            self.routes.iter().copied().for_each(visit);
            return;
        };
        let range = actual
            .get(selector.position)
            .expect("selector position is below the bucket minimum");
        let (start, end) = range.bounds();
        let raw = &actual.path[start..end];
        let decoded = (mode == PathMode::PercentDecoded && raw.as_bytes().contains(&b'%'))
            .then(|| percent_encoding::percent_decode_str(raw).decode_utf8_lossy());
        let value = decoded.as_deref().unwrap_or(raw);
        if let Some(ids) = selector.literals.get(value) {
            ids.iter().copied().for_each(&mut visit);
        }
        selector.parameters.iter().copied().for_each(visit);
    }
}

fn select_literal(entries: &[RouteEntry], routes: &[usize]) -> Option<LiteralSelector> {
    let width = entries[*routes.first()?].segments.len();
    let mut selected = None;
    for position in 0..width {
        let mut literals = HashMap::<Box<str>, Vec<usize>>::new();
        let mut parameters = Vec::new();
        for &id in routes {
            match &entries[id].segments[position] {
                TemplateSegment::Literal(literal) => {
                    literals.entry(literal.clone()).or_default().push(id);
                }
                TemplateSegment::Parameter => parameters.push(id),
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
            .map(|(literal, ids)| (literal, ids.into()))
            .collect(),
        parameters: parameters.into(),
    })
}

struct RequestSegments<'a> {
    path: &'a str,
    inline: [PathRange; INLINE_SEGMENTS],
    overflow: Vec<PathRange>,
    len: usize,
}

impl<'a> RequestSegments<'a> {
    #[inline]
    fn parse(path: &'a str) -> Option<Self> {
        if path.is_empty() {
            return Some(Self {
                path,
                inline: [PathRange::default(); INLINE_SEGMENTS],
                overflow: Vec::new(),
                len: 1,
            });
        }
        let remainder = path.strip_prefix('/')?;
        let mut result = Self {
            path,
            inline: [PathRange::default(); INLINE_SEGMENTS],
            overflow: Vec::new(),
            len: 0,
        };
        let mut start = 1;
        for segment in remainder.split('/') {
            result.push(PathRange::new(start, start + segment.len())?);
            start += segment.len() + 1;
        }
        Some(result)
    }

    fn push(&mut self, range: PathRange) {
        if let Some(slot) = self.inline.get_mut(self.len) {
            *slot = range;
        } else {
            self.overflow.push(range);
        }
        self.len += 1;
    }

    #[inline]
    fn get(&self, position: usize) -> Option<PathRange> {
        if position >= self.len {
            None
        } else if position < self.inline.len() {
            Some(self.inline[position])
        } else {
            self.overflow.get(position - self.inline.len()).copied()
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PathRange {
    start: u32,
    end: u32,
}

impl PathRange {
    fn new(start: usize, end: usize) -> Option<Self> {
        Some(Self {
            start: u32::try_from(start).ok()?,
            end: u32::try_from(end).ok()?,
        })
    }

    fn start(self) -> usize {
        self.start as usize
    }

    fn bounds(self) -> (usize, usize) {
        (self.start(), self.end as usize)
    }
}

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
        let mut standard = 0;
        let mut extensions = Vec::new();
        for method in methods {
            if let Some(bit) = method_bit(method.as_str()) {
                standard |= bit;
            } else if !extensions.contains(&method) {
                extensions.push(method);
            }
        }
        Self {
            any: false,
            standard,
            extensions: extensions.into(),
        }
    }

    #[inline]
    fn matches_str(&self, method: &str) -> bool {
        self.any
            || method_bit(method).is_some_and(|bit| self.standard & bit != 0)
            || self
                .extensions
                .iter()
                .any(|candidate| candidate.as_str() == method)
    }

    fn standard_bits(&self) -> u16 {
        if self.any {
            STANDARD_METHODS
        } else {
            self.standard
        }
    }
}

fn method_bit(method: &str) -> Option<u16> {
    Some(match method {
        "DELETE" => 1 << 0,
        "GET" => 1 << 1,
        "HEAD" => 1 << 2,
        "OPTIONS" => 1 << 3,
        "PATCH" => 1 << 4,
        "POST" => 1 << 5,
        "PUT" => 1 << 6,
        "CONNECT" => 1 << 7,
        "TRACE" => 1 << 8,
        _ => return None,
    })
}
