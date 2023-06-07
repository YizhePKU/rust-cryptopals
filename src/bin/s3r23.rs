use crypto::mt19937::{inv_temper, Mt19937};

fn main() {
    let mut mt = Mt19937::new(1234);

    // collect 624 outputs
    let mut outputs = [0; 624];
    for i in 0..624 {
        outputs[i] = mt.gen();
    }

    // invert outputs to state
    for i in 0..624 {
        outputs[i] = inv_temper(outputs[i]);
    }

    // splice state to a new Mt19937 instance
    let mut mt2 = Mt19937::new(8848);
    mt2.state.extend_from_slice(&outputs);

    // now mt and mt2 should output the same number sequence
    println!("{} - {}", mt.gen(), mt2.gen());
    println!("{} - {}", mt.gen(), mt2.gen());
    println!("{} - {}", mt.gen(), mt2.gen());
}
