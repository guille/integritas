use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::fs;
use std::io::Write;
use tempfile::TempDir;

fn create_file(dir: &std::path::Path, name: &str, size: usize) {
    let data: Vec<u8> = (0..size).map(|i| u8::try_from(i % 256).unwrap()).collect();
    let mut f = fs::File::create(dir.join(name)).unwrap();
    f.write_all(&data).unwrap();
}

fn bench_hash_throughput(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();

    let sizes: &[(usize, &str)] = &[
        (1024, "1KB"),
        (1024 * 1024, "1MB"),
        (10 * 1024 * 1024, "10MB"),
        (100 * 1024 * 1024, "100MB"),
    ];

    let mut group = c.benchmark_group("hash_file");

    for (size, label) in sizes {
        let filename = format!("test_{label}.bin");
        create_file(dir.path(), &filename, *size);
        let path = dir.path().join(&filename);

        group.throughput(Throughput::Bytes(*size as u64));

        // Standard hash (uses update_rayon for files > threshold)
        group.bench_with_input(BenchmarkId::new("default", label), size, |b, _| {
            b.iter(|| integritas::hash_file(&path).unwrap());
        });

        // With fadvise
        group.bench_with_input(BenchmarkId::new("with_fadvise", label), size, |b, _| {
            b.iter(|| integritas::hash_file_with_advise(&path, true).unwrap());
        });
    }

    group.finish();
}

fn bench_many_files(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();

    // Create 100 x 4KB files
    for i in 0..100 {
        create_file(dir.path(), &format!("file_{i}.bin"), 4096);
    }

    let mut group = c.benchmark_group("compute");
    group.throughput(Throughput::Elements(100));

    group.bench_function("sequential", |b| {
        b.iter(|| integritas::manifest::compute(dir.path()).unwrap());
    });

    group.bench_function("parallel_8", |b| {
        b.iter(|| integritas::manifest::compute_with_threads(dir.path(), 8, None, &[]).unwrap());
    });

    group.finish();
}

criterion_group!(benches, bench_hash_throughput, bench_many_files);
criterion_main!(benches);
