//! Allocation assertions for request-time route selection.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use brz_http_router::{IndexedRouteRule, PathMode, RouteIndex, RouteRule, RouteTable};
use http::Method;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

struct Counted;

// SAFETY: Every operation preserves its arguments and forwards ownership to
// the same System allocator. Counting uses allocation-free thread-local state.
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_one();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_one();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count_one();
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counted = Counted;

fn count_one() {
    let _ = ALLOCATIONS.try_with(|slot| {
        if let Some(count) = slot.get() {
            slot.set(Some(count + 1));
        }
    });
}

fn allocations(work: impl FnOnce()) -> usize {
    ALLOCATIONS.with(|slot| slot.set(Some(0)));
    work();
    ALLOCATIONS.with(|slot| slot.replace(None).unwrap())
}

#[test]
fn ordinary_exact_and_dynamic_routes_do_not_allocate_while_matching() {
    let table = RouteTable::compile([
        RouteRule::new("/api/status", vec![Method::GET]),
        RouteRule::new("/api/users/:id", vec![Method::GET]),
    ])
    .unwrap();
    let index = RouteIndex::compile([IndexedRouteRule::new(
        "/api/users/:id",
        vec![Method::GET],
        1,
    )])
    .unwrap();

    let count = allocations(|| {
        assert!(table.matches(&Method::GET, "/api/status"));
        assert!(table.matches(&Method::GET, "/api/users/42"));
        assert_eq!(
            index
                .resolve("GET", "/api/users/42", PathMode::Raw)
                .selected()
                .unwrap()
                .captures()
                .get(0),
            Some((11, 13))
        );
    });
    assert_eq!(count, 0);
}
