use criterion::{
    black_box, criterion_group, criterion_main,
    Criterion, BenchmarkId, Throughput
};
use core::time::Duration;
use w3f_bls::{KeypairVT, PublicKey, TinyBLS377};
use etf_crypto_primitives::dpss::{DoubleSecret, Keypair};
use rand_core::OsRng;

/// this runs the 'worst case scenario' for the ACSS algorithm
/// here we create a resharing and then the committee linearly recovers it on a single thread
/// i.e. they run the recover algorithm one after the other
fn acss_reshare_with_single_threaded_recovery_tinybls377(
    double_secret: DoubleSecret<TinyBLS377>,
    committee_public: &[PublicKey<TinyBLS377>],
    committee_keys: &[KeypairVT<TinyBLS377>],
    t: u8,
) {
    let resharing = double_secret.reshare(committee_public, t, &mut OsRng).unwrap();
    committee_keys.iter().enumerate().for_each(|(idx, kp)| {
        let sk = Keypair(kp.clone());
        sk.recover(resharing[idx].1.clone(), t).unwrap();
    });
}

fn acss(c: &mut Criterion) {
    static KB: usize = 1024;   

    let mut group = c.benchmark_group("acss");
    for size in [3, 5, 10, 20, 50].iter() {
        let keys: Vec<KeypairVT<TinyBLS377>> = (0..*size).map(|_| {
            KeypairVT::<TinyBLS377>::generate(&mut OsRng)
        }).collect();

        let initial_committee_public_keys = keys.iter().map(|kp| kp.public).collect::<Vec<_>>();

        group.throughput(Throughput::Bytes(KB as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                acss_reshare_with_single_threaded_recovery_tinybls377(
                    black_box(DoubleSecret::rand(&mut OsRng)), 
                    black_box(&initial_committee_public_keys.clone()),
                    black_box(&keys.clone()),
                    black_box(size)
                )
            });
        });
    }
    group.finish();
}

criterion_group!(benches, acss);
criterion_main!(benches);
