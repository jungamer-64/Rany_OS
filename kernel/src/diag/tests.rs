use super::*;

#[test_case]
fn test_histogram() {
    let hist = Histogram::new();

    for i in 1..=100 {
        hist.record(i);
    }

    let stats = hist.stats();
    assert_eq!(stats.count, 100);
    assert_eq!(stats.min, 1);
    assert_eq!(stats.max, 100);
}

#[test_case]
fn test_histogram_percentile() {
    let hist = Histogram::new();

    for i in 1..=100 {
        hist.record(i);
    }

    let p50 = hist.percentile(50.0);
    let p99 = hist.percentile(99.0);
    assert!(p50 <= p99);
}

#[test_case]
fn test_trace_event() {
    let buf = TraceBuffer::new(100);
    buf.enable();
    buf.record(TracePointId(1), 0, 42);

    let events = buf.drain();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, 42);
}

#[test_case]
fn test_benchmark_runner() {
    let mut counter = 0u64;
    let result = BenchmarkRunner::run("test", 1000, || {
        counter += 1;
    });

    assert_eq!(result.iterations, 1000);
    assert!(result.cycles_per_op > 0);
}
