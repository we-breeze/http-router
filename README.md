# brz-http-router

`brz-http-router` selects routes for the Wegent hybrid gateway. It compiles
literal paths and `:parameter` / terminal `*rest` templates once. Calls to
`RouteTable::matches` do not allocate or lock.

Exact paths use a byte-length direct index. The common case, where one exact
path has a given length, avoids hashing entirely; only same-length paths use a
collision map. Template paths are grouped by segment count and use the most
selective literal position as a candidate selector.

The crate is intentionally scoped to the current Breeze gateway contract:
exact paths, `:parameter` segments, and terminal `*catch_all` segments. Query
strings are excluded by callers before matching.
