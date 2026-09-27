# brz-http-router

`brz-http-router` is the shared route-selection core for Breeze HTTP runtimes.
It compiles literal paths and `:parameter` / terminal `*rest` templates once.
`RouteTable` provides the gateway's boolean interface; `RouteIndex` also
returns a stable route id, priority selection, allowed standard methods, and
raw capture ranges for `brz-http-server`.

Exact paths use a byte-length direct index. The common case, where one exact
path has a given length, avoids hashing; only same-length paths use the
collision map. Template paths are grouped by segment count and use the most
selective literal position as a candidate selector.

Ordinary paths with at most eight segments match without allocation. Deeper
paths use an overflow vector and have no fixed matching limit. The server can
request per-segment percent-decoded literal comparison while retaining raw
capture ranges. Raw `/` bytes always establish boundaries, so an encoded slash
stays inside one capture. The gateway keeps raw comparison and its existing
nonempty catch-all behavior. Query strings are excluded by callers.
