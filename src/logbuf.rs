//! An in-memory tail of the log, for `ctl debug logs`: the lines that matter
//! are available from the running proxy itself, whatever the configured log
//! level and wherever stdout happens to go.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::Context;

/// How many lines to keep.
const CAPACITY: usize = 500;

#[derive(Clone, Debug, serde::Serialize)]
pub struct LogLine {
    pub time: SystemTime,
    pub level: &'static str,
    pub target: String,
    /// The message followed by its fields as `key=value`.
    pub message: String,
}

#[derive(Default)]
pub struct LogBuffer {
    lines: Mutex<VecDeque<LogLine>>,
}

impl LogBuffer {
    fn push(&self, line: LogLine) {
        let mut lines = self.lines.lock().unwrap();
        if lines.len() == CAPACITY {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    /// The most recent `limit` lines at `min_level` or above, oldest first.
    pub fn tail(&self, min_level: Level, limit: usize) -> Vec<LogLine> {
        let lines = self.lines.lock().unwrap();
        let mut tail: Vec<LogLine> = lines
            .iter()
            .rev()
            // More severe levels compare as smaller.
            .filter(|line| {
                line.level
                    .parse::<Level>()
                    .is_ok_and(|level| level <= min_level)
            })
            .take(limit)
            .cloned()
            .collect();
        tail.reverse();
        tail
    }

    /// Lines at `level` or above within the last `window`.
    pub fn count_since(&self, level: Level, window: std::time::Duration) -> usize {
        let lines = self.lines.lock().unwrap();
        lines
            .iter()
            .filter(|line| line.level.parse::<Level>().is_ok_and(|l| l <= level))
            .filter(|line| line.time.elapsed().is_ok_and(|age| age <= window))
            .count()
    }

    /// A tracing layer feeding this buffer: everything the proxy itself says
    /// at INFO and above, and warnings and errors from its dependencies
    /// (matrix-sdk-crypto explains failed decryptions there).
    pub fn layer<S>(self: &Arc<Self>) -> impl Layer<S> + use<S>
    where
        S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        BufferLayer(self.clone()).with_filter(
            Targets::new()
                .with_default(Level::WARN)
                .with_target(env!("CARGO_CRATE_NAME"), Level::INFO),
        )
    }
}

struct BufferLayer(Arc<LogBuffer>);

impl<S: Subscriber> Layer<S> for BufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = LineVisitor::default();
        event.record(&mut visitor);
        let metadata = event.metadata();
        self.0.push(LogLine {
            time: SystemTime::now(),
            level: metadata.level().as_str(),
            target: metadata.target().to_owned(),
            message: visitor.finish(),
        });
    }
}

#[derive(Default)]
struct LineVisitor {
    message: String,
    fields: String,
}

impl LineVisitor {
    fn finish(self) -> String {
        match (self.message.is_empty(), self.fields.is_empty()) {
            (_, true) => self.message,
            (true, false) => self.fields.trim_start().to_owned(),
            (false, false) => format!("{}{}", self.message, self.fields),
        }
    }
}

impl Visit for LineVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt as _;

    fn capture(emit: impl FnOnce()) -> Arc<LogBuffer> {
        let buffer = Arc::new(LogBuffer::default());
        let subscriber = tracing_subscriber::registry().with(buffer.layer());
        tracing::subscriber::with_default(subscriber, emit);
        buffer
    }

    #[test]
    fn keeps_messages_with_their_fields() {
        let buffer = capture(|| {
            tracing::info!(room_id = "!r:example.org", count = 3, "shared room key");
            tracing::warn!(error = ?std::io::ErrorKind::TimedOut, "upstream failed");
        });
        let lines = buffer.tail(Level::INFO, 10);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].level, "INFO");
        assert_eq!(
            lines[0].message,
            "shared room key room_id=!r:example.org count=3"
        );
        assert!(lines[0].target.starts_with("ement_e2ee"));
        assert_eq!(lines[1].message, "upstream failed error=TimedOut");
    }

    #[test]
    fn keeps_what_matters_regardless_of_verbosity() {
        let buffer = capture(|| {
            // Our own chatter below INFO is not worth the memory ...
            tracing::debug!("pump tick");
            tracing::trace!("request");
            // ... nor is a dependency's INFO, but its warnings are.
            tracing::info!(target: "matrix_sdk_crypto::machine", "created olm machine");
            tracing::warn!(target: "matrix_sdk_crypto::olm", "failed to decrypt");
            tracing::error!("store error");
        });
        let messages: Vec<String> = buffer
            .tail(Level::INFO, 10)
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(messages, ["failed to decrypt", "store error"]);
    }

    #[test]
    fn tail_filters_by_level_and_limits() {
        let buffer = capture(|| {
            tracing::info!("one");
            tracing::warn!("two");
            tracing::error!("three");
            tracing::warn!("four");
        });
        let messages = |level, limit| -> Vec<String> {
            buffer
                .tail(level, limit)
                .into_iter()
                .map(|line| line.message)
                .collect()
        };
        assert_eq!(messages(Level::WARN, 10), ["two", "three", "four"]);
        assert_eq!(messages(Level::ERROR, 10), ["three"]);
        // The newest lines win, still in chronological order.
        assert_eq!(messages(Level::INFO, 2), ["three", "four"]);
        assert_eq!(
            buffer.count_since(Level::WARN, std::time::Duration::from_secs(60)),
            3
        );
        assert_eq!(
            buffer.count_since(Level::ERROR, std::time::Duration::from_secs(60)),
            1
        );
    }

    #[test]
    fn memory_is_bounded() {
        let buffer = capture(|| {
            for i in 0..CAPACITY + 20 {
                tracing::info!("line {i}");
            }
        });
        let lines = buffer.tail(Level::INFO, usize::MAX);
        assert_eq!(lines.len(), CAPACITY);
        assert_eq!(lines[0].message, "line 20");
    }
}
