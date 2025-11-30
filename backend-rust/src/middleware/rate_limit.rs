// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Rate Limiting Middleware
// ============================================================================

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Duration, Utc};

use crate::AppState;

#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<DateTime<Utc>>>>>,
    max_requests: usize,
    window_seconds: i64,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_seconds: i64) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_seconds,
        }
    }

    pub async fn check_rate_limit(&self, key: &str) -> bool {
        let mut requests = self.requests.write().await;
        let now = Utc::now();
        let window_start = now - Duration::seconds(self.window_seconds);

        // Get or create request history for this key
        let history = requests.entry(key.to_string()).or_insert_with(Vec::new);

        // Remove expired entries
        history.retain(|&timestamp| timestamp > window_start);

        // Check if limit exceeded
        if history.len() >= self.max_requests {
            return false;
        }

        // Add current request
        history.push(now);

        true
    }

    pub async fn cleanup_old_entries(&self) {
        let mut requests = self.requests.write().await;
        let now = Utc::now();
        let window_start = now - Duration::seconds(self.window_seconds);

        requests.retain(|_, history| {
            history.retain(|&timestamp| timestamp > window_start);
            !history.is_empty()
        });
    }
}

/// Rate limiting middleware based on IP address
pub async fn rate_limit_middleware(
    State(_state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Get rate limiter from request extensions
    let rate_limiter = request
        .extensions()
        .get::<RateLimiter>()
        .cloned()
        .unwrap_or_else(|| RateLimiter::new(100, 60)); // Default: 100 requests per minute

    let client_ip = addr.ip().to_string();

    if !rate_limiter.check_rate_limit(&client_ip).await {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(json!({
                "error": "Rate limit exceeded. Please try again later."
            })),
        ));
    }

    Ok(next.run(request).await)
}

/// Strict rate limiting for authentication endpoints
pub async fn auth_rate_limit_middleware(
    State(_state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let rate_limiter = RateLimiter::new(5, 60); // 5 requests per minute for auth

    let client_ip = addr.ip().to_string();

    if !rate_limiter.check_rate_limit(&client_ip).await {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(json!({
                "error": "Too many authentication attempts. Please try again in a minute."
            })),
        ));
    }

    Ok(next.run(request).await)
}
