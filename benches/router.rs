use std::hint::black_box;
use std::time::Instant;

use brz_http_router::{RouteRule, RouteTable};
use http::Method;

fn rules(count: usize) -> Vec<RouteRule> {
    (0..count)
        .flat_map(|id| {
            [
                RouteRule::new(format!("/api/group-{id:04}/status"), vec![Method::GET]),
                RouteRule::new(format!("/api/group-{id:04}/:id"), vec![Method::GET]),
            ]
        })
        .collect()
}

fn suffix_rules(count: usize) -> Vec<RouteRule> {
    (0..count)
        .map(|id| RouteRule::new(format!("/api/:id/action-{id:04}"), vec![Method::GET]))
        .collect()
}

fn measure(routes: &RouteTable, path: &str) -> f64 {
    const ITERATIONS: u32 = 20_000;
    for _ in 0..1000 {
        black_box(routes.matches(&Method::GET, black_box(path)));
    }
    let mut samples = [0.0; 3];
    for sample in &mut samples {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(routes.matches(&Method::GET, black_box(path)));
        }
        *sample = start.elapsed().as_secs_f64() * 1e9 / f64::from(ITERATIONS);
    }
    samples.sort_by(f64::total_cmp);
    samples[1]
}

fn main() {
    println!("Route selection only; median ns/op; no I/O or handler invocation.");
    println!("case\trouter(24 APIs)");
    let routes = RouteTable::compile(rules(24)).unwrap();
    for (case, path) in [
        ("static-first", "/api/group-0000/status"),
        ("static-last", "/api/group-0023/status"),
        ("parameter-first", "/api/group-0000/123"),
        ("parameter-last", "/api/group-0023/123"),
        ("miss", "/api/missing/no-match"),
    ] {
        println!("{case}\t{:.0}", measure(&routes, path));
    }
    for count in [128, 512] {
        let routes = RouteTable::compile(rules(count)).unwrap();
        let path = format!("/api/group-{:04}/123", count - 1);
        println!(
            "router({count} APIs), parameter-last\t{:.0}",
            measure(&routes, &path)
        );
    }
    let suffix = RouteTable::compile(suffix_rules(512)).unwrap();
    println!(
        "router(512 APIs), literal-suffix-last\t{:.0}",
        measure(&suffix, "/api/123/action-0511")
    );
}
