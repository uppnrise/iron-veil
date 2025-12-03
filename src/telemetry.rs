//! OpenTelemetry integration for distributed tracing and metrics.
//!
//! This module configures the OTLP exporter for sending traces and metrics
//! to observability backends like Jaeger, Grafana Tempo, or any OTEL-compatible collector.

use crate::config::TelemetryConfig;
use anyhow::Result;
use opentelemetry::trace::TracerProvider;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    runtime,
    trace::{RandomIdGenerator, Sampler, TracerProvider as SdkTracerProvider},
    Resource,
};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initializes the telemetry subsystem with OpenTelemetry.
///
/// Returns a guard that will shut down the tracer provider when dropped.
pub fn init_telemetry(config: Option<&TelemetryConfig>) -> Result<Option<TelemetryGuard>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,iron_veil=debug"));

    match config {
        Some(cfg) if cfg.enabled => {
            // Build the OTLP exporter
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&cfg.otlp_endpoint)
                .build()?;

            // Build the tracer provider
            let provider = SdkTracerProvider::builder()
                .with_batch_exporter(exporter, runtime::Tokio)
                .with_sampler(Sampler::AlwaysOn)
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(Resource::new(vec![
                    KeyValue::new("service.name", cfg.service_name.clone()),
                    KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                ]))
                .build();

            // Get a tracer from the provider
            let tracer = provider.tracer("iron-veil");

            // Create the OpenTelemetry layer for tracing
            let otel_layer = OpenTelemetryLayer::new(tracer);

            // Initialize the subscriber with both fmt (console) and OTEL layers
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().with_target(true))
                .with(otel_layer)
                .init();

            tracing::info!(
                endpoint = %cfg.otlp_endpoint,
                service = %cfg.service_name,
                "OpenTelemetry tracing initialized"
            );

            Ok(Some(TelemetryGuard { provider }))
        }
        _ => {
            // No telemetry config or disabled - just use console logging
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_target(true)
                        .with_level(true),
                )
                .init();

            tracing::info!("Telemetry disabled, using console logging only");
            Ok(None)
        }
    }
}

/// Guard that ensures proper shutdown of the telemetry provider.
/// When dropped, it will flush any pending traces.
pub struct TelemetryGuard {
    provider: SdkTracerProvider,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown() {
            eprintln!("Error shutting down tracer provider: {:?}", e);
        }
    }
}

/// Creates a span for database proxy operations.
/// Use this macro to instrument key code paths.
#[macro_export]
macro_rules! span_proxy {
    ($name:expr) => {
        tracing::info_span!("proxy", operation = $name)
    };
    ($name:expr, $($field:tt)*) => {
        tracing::info_span!("proxy", operation = $name, $($field)*)
    };
}
