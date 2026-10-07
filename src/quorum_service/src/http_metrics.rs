//! Gap 11: per-route request count, error count and latency histogram.
//!
//! Label cardinality is bounded by construction: the `route` label is the
//! router's MATCHED PATTERN (e.g. `/invoices/:id/grant`), never the raw path,
//! so invoice ids and anything else a client puts in a URL can never become a
//! label. Requests that match no route share the single label `unmatched`.
//! The method is normalised to a fixed set. As a last guard the registry holds
//! at most `MAX_SERIES` distinct (route, method) series; further ones fold
//! into `route="overflow"`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::Response;

/// Upper bounds (seconds) of the latency histogram buckets; `+Inf` is implicit.
pub const BUCKETS_S: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const MAX_SERIES: usize = 64;
const UNMATCHED: &str = "unmatched";
const OVERFLOW: &str = "overflow";

#[derive(Default, Clone)]
struct Series {
    count: u64,
    errors_4xx: u64,
    errors_5xx: u64,
    /// Non-cumulative per-bucket counts; the last slot is `+Inf`.
    buckets: [u64; BUCKETS_S.len() + 1],
    sum_seconds: f64,
}

#[derive(Default)]
pub struct HttpMetrics {
    series: Mutex<BTreeMap<(String, &'static str), Series>>,
}

fn norm_method(m: &str) -> &'static str {
    match m {
        "GET" => "GET",
        "POST" => "POST",
        "DELETE" => "DELETE",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        _ => "OTHER",
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

impl HttpMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<(String, &'static str), Series>> {
        self.series
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Record one finished request. Never panics; a poisoned lock is recovered
    /// (counters stay usable) rather than propagated.
    pub fn record(&self, route: &str, method: &str, status: u16, elapsed: Duration) {
        let method = norm_method(method);
        let mut map = self.lock();
        let key = (route.to_string(), method);
        let key = if map.contains_key(&key) || map.len() < MAX_SERIES {
            key
        } else {
            (OVERFLOW.to_string(), method)
        };
        let s = map.entry(key).or_default();
        s.count += 1;
        match status {
            400..=499 => s.errors_4xx += 1,
            500..=599 => s.errors_5xx += 1,
            _ => {}
        }
        let secs = elapsed.as_secs_f64();
        let idx = BUCKETS_S
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(BUCKETS_S.len());
        if let Some(slot) = s.buckets.get_mut(idx) {
            *slot += 1;
        }
        s.sum_seconds += secs;
    }

    /// Prometheus text exposition for the HTTP series.
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let map = self.lock();
        let mut o = String::new();
        let _ = writeln!(
            o,
            "# HELP ciphersettle_http_requests_total HTTP requests by matched route pattern and method."
        );
        let _ = writeln!(o, "# TYPE ciphersettle_http_requests_total counter");
        for ((r, m), s) in map.iter() {
            let _ = writeln!(
                o,
                "ciphersettle_http_requests_total{{route=\"{}\",method=\"{m}\"}} {}",
                esc(r),
                s.count
            );
        }
        let _ = writeln!(
            o,
            "# HELP ciphersettle_http_errors_total HTTP responses with 4xx/5xx status."
        );
        let _ = writeln!(o, "# TYPE ciphersettle_http_errors_total counter");
        for ((r, m), s) in map.iter() {
            for (class, n) in [("4xx", s.errors_4xx), ("5xx", s.errors_5xx)] {
                let _ = writeln!(
                    o,
                    "ciphersettle_http_errors_total{{route=\"{}\",method=\"{m}\",class=\"{class}\"}} {n}",
                    esc(r)
                );
            }
        }
        let _ = writeln!(
            o,
            "# HELP ciphersettle_http_request_duration_seconds HTTP handler latency."
        );
        let _ = writeln!(
            o,
            "# TYPE ciphersettle_http_request_duration_seconds histogram"
        );
        for ((r, m), s) in map.iter() {
            let l = format!("route=\"{}\",method=\"{m}\"", esc(r));
            let mut cum = 0u64;
            for (i, b) in BUCKETS_S.iter().enumerate() {
                cum += s.buckets.get(i).copied().unwrap_or(0);
                let _ = writeln!(
                    o,
                    "ciphersettle_http_request_duration_seconds_bucket{{{l},le=\"{b}\"}} {cum}"
                );
            }
            let _ = writeln!(
                o,
                "ciphersettle_http_request_duration_seconds_bucket{{{l},le=\"+Inf\"}} {}",
                s.count
            );
            let _ = writeln!(
                o,
                "ciphersettle_http_request_duration_seconds_sum{{{l}}} {}",
                s.sum_seconds
            );
            let _ = writeln!(
                o,
                "ciphersettle_http_request_duration_seconds_count{{{l}}} {}",
                s.count
            );
        }
        o
    }
}

/// axum middleware: times the request and records it under the matched route
/// pattern (or `unmatched`).
pub async fn track(State(m): State<Arc<HttpMetrics>>, req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| UNMATCHED.to_string());
    let method = req.method().as_str().to_string();
    let start = Instant::now();
    let resp = next.run(req).await;
    m.record(&route, &method, resp.status().as_u16(), start.elapsed());
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn counts_requests_and_splits_4xx_from_5xx() {
        let m = HttpMetrics::new();
        m.record("/a", "GET", 200, ms(1));
        m.record("/a", "GET", 404, ms(1));
        m.record("/a", "GET", 403, ms(1));
        m.record("/a", "GET", 500, ms(1));
        m.record("/a", "GET", 302, ms(1));
        let t = m.render();
        for want in [
            "ciphersettle_http_requests_total{route=\"/a\",method=\"GET\"} 5\n",
            "ciphersettle_http_errors_total{route=\"/a\",method=\"GET\",class=\"4xx\"} 2\n",
            "ciphersettle_http_errors_total{route=\"/a\",method=\"GET\",class=\"5xx\"} 1\n",
        ] {
            assert!(t.contains(want), "missing {want:?} in {t}");
        }
    }

    #[test]
    fn histogram_is_cumulative_with_inf_sum_and_count() {
        let m = HttpMetrics::new();
        m.record("/h", "POST", 200, ms(3)); // <= 0.005
        m.record("/h", "POST", 200, ms(30)); // <= 0.05
        m.record("/h", "POST", 200, Duration::from_secs(60)); // +Inf only
        let t = m.render();
        let l = "route=\"/h\",method=\"POST\"";
        for want in [
            format!("duration_seconds_bucket{{{l},le=\"0.005\"}} 1\n"),
            format!("duration_seconds_bucket{{{l},le=\"0.025\"}} 1\n"),
            format!("duration_seconds_bucket{{{l},le=\"0.05\"}} 2\n"),
            format!("duration_seconds_bucket{{{l},le=\"10\"}} 2\n"),
            format!("duration_seconds_bucket{{{l},le=\"+Inf\"}} 3\n"),
            format!("duration_seconds_count{{{l}}} 3\n"),
        ] {
            assert!(t.contains(&want), "missing {want:?} in {t}");
        }
        assert!(t.contains(&format!("duration_seconds_sum{{{l}}} 60.033")));
        assert!(t.contains("# TYPE ciphersettle_http_request_duration_seconds histogram\n"));
    }

    #[test]
    fn unknown_methods_collapse_and_series_count_is_bounded() {
        let m = HttpMetrics::new();
        m.record("/x", "BREW", 200, ms(1));
        m.record("/x", "PROPFIND", 200, ms(1));
        assert!(m
            .render()
            .contains("ciphersettle_http_requests_total{route=\"/x\",method=\"OTHER\"} 2\n"));
        for i in 0..(MAX_SERIES * 3) {
            m.record(&format!("/r{i}"), "GET", 200, ms(1));
        }
        let t = m.render();
        let n = t
            .lines()
            .filter(|l| l.starts_with("ciphersettle_http_requests_total{"))
            .count();
        assert!(n <= MAX_SERIES + 2, "series not bounded: {n}");
        assert!(t.contains("route=\"overflow\""));
    }

    async fn ok() -> &'static str {
        "ok"
    }
    async fn boom() -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn app(m: Arc<HttpMetrics>) -> Router {
        Router::new()
            .route("/invoices/:id/grant", post(ok))
            .route("/boom", get(boom))
            .layer(axum::middleware::from_fn_with_state(m, track))
    }

    async fn call(app: &Router, method: &str, path: &str) -> StatusCode {
        let req = HttpRequest::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .expect("request");
        app.clone().oneshot(req).await.expect("oneshot").status()
    }

    #[tokio::test]
    async fn middleware_labels_by_pattern_not_raw_path_and_folds_unmatched() {
        let m = Arc::new(HttpMetrics::new());
        let a = app(m.clone());
        assert_eq!(
            call(&a, "POST", "/invoices/SECRET-INV-1/grant").await,
            StatusCode::OK
        );
        assert_eq!(
            call(&a, "POST", "/invoices/SECRET-INV-2/grant").await,
            StatusCode::OK
        );
        assert_eq!(
            call(&a, "GET", "/boom").await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(call(&a, "GET", "/nope/1").await, StatusCode::NOT_FOUND);
        assert_eq!(call(&a, "GET", "/nope/2").await, StatusCode::NOT_FOUND);
        let t = m.render();
        assert!(!t.contains("SECRET"), "raw path leaked into labels: {t}");
        assert!(!t.contains("nope"), "raw path leaked into labels: {t}");
        for want in [
            "ciphersettle_http_requests_total{route=\"/invoices/:id/grant\",method=\"POST\"} 2\n",
            "ciphersettle_http_errors_total{route=\"/boom\",method=\"GET\",class=\"5xx\"} 1\n",
            "ciphersettle_http_requests_total{route=\"unmatched\",method=\"GET\"} 2\n",
            "ciphersettle_http_errors_total{route=\"unmatched\",method=\"GET\",class=\"4xx\"} 2\n",
        ] {
            assert!(t.contains(want), "missing {want:?} in {t}");
        }
    }
}
