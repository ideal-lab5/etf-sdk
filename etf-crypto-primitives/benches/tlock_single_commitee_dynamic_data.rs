use criterion::{
    black_box, criterion_group, criterion_main,
    Criterion, BenchmarkId, Throughput
};
use ark_ff::UniformRand;
use w3f_bls::{EngineBLS, KeypairVT, PublicKey, TinyBLS377};
use etf_crypto_primitives::encryption::tlock::*;
use etf_crypto_primitives::ibe::fullident::*;
use rand_core::OsRng;

/// encrypts a message for the identity and then decrypts it after preparing a bls sig
/// this expects on a single signature but tests many different input data sizes
fn tlock_tinybls377<E: EngineBLS>(
    msk: SecretKey<E>,
    message: Vec<u8>,
    id: Identity,
) {
    let ct = msk.encrypt(&message, id.clone(), &mut OsRng).unwrap();
    let m = ct.decrypt(vec![id.extract(msk.0)]).unwrap();
}

fn tlock_single_commitee_dynamic_data(c: &mut Criterion) {
    static KB: usize = 1024;   

    let s1 = <TinyBLS377 as EngineBLS>::Scalar::rand(&mut OsRng);
    let id = Identity::new(b"test");

    let mut group = c.benchmark_group("tlock_single_commitee_dynamic_data");
    for size in [KB, 2*KB, 4*KB, 8*KB, 16*KB, 128*KB].iter() {

        let mut dummy_data = Vec::with_capacity(*size);
        (0..*size).for_each(|i| dummy_data.push(i as u8));

        group.throughput(Throughput::Bytes(KB as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                tlock_tinybls377(
                    black_box(SecretKey::<TinyBLS377>::new(s1)), 
                    black_box(dummy_data.clone()),
                    black_box(id.clone()),
                );
            });
        });
    }
    group.finish();
}

criterion_group!(benches, tlock_single_commitee_dynamic_data);
criterion_main!(benches);
