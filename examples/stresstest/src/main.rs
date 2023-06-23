use rand::distributions::{Alphanumeric, DistString};
use rusty_leveldb::{Options, DB};

const KEY_LEN: usize = 4;
const VAL_LEN: usize = 8;

fn main() {
    let N = 100_000;
    let m = 10;
    let mut entries = 0;

    for i in 0..m {
        let mut options = Options::default();
        options.compression_type = rusty_leveldb::CompressionType::CompressionSnappy;

        let mut db = DB::open("stress_test", options).unwrap();

        write(&mut db, N);
        entries += N;
        println!("Wrote {} entries ({}/{})", entries, i + 1, m);

        let s = read(&mut db, N);
        println!("Read back {} entries (found {}) ({}/{})", N, s, i + 1, m);
    }
}

fn gen_string(n: usize) -> String {
    Alphanumeric
        .sample_string(&mut rand::thread_rng(), n)
        .to_lowercase()
}

fn write(db: &mut DB, n: usize) {
    for _ in 0..n {
        db.put(gen_string(KEY_LEN).as_bytes(), gen_string(VAL_LEN).as_bytes()).unwrap();
    }

    db.flush().unwrap();
}

fn read(db: &mut DB, n: usize) -> usize {
    let mut succ = 0;
    time_test::time_test!("read");
    for _ in 0..n {
        let k = gen_string(KEY_LEN);

        if let Some(_) = db.get(k.as_bytes()) {
            succ += 1;
        }
    }
    succ
}
