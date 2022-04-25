use colored::*;
use ct_account::account::Account;
use ct_account::confidential_transaction::ConfidentialTransaction;
use ct_account::ring_confidential_transaction::RingCT;
use ct_token::prove::NonnegativeProof;
use ct_token::token::*;
use rand::prelude::*;

fn main() {
    println_green("欢迎来到环机密性交易，机密性交易主要保护以下两点：\n 1.交易金额\n 2.接收方地址\n 3.发送方地址");

    let ring_size = wait_for_number("请输入环成员个数(2到20之间的整数): ", 2, 20);

    let input_size = wait_for_number(
        "环机密支持多输入，请输入\"输入交易总数量\"(1到100之间的整数): ",
        1,
        100,
    );
    let mut input_amount = Vec::with_capacity(input_size);
    for i in 1..input_size + 1 {
        input_amount.push(wait_for_number(
            &format!("请输入第{}笔输入交易金额(1到10000之间的整数)", i),
            1,
            10000,
        ) as u64);
    }

    let output_size = wait_for_number(
        "请创建输出账户个数(1到100之间的整数),并为每个输出账户设置转账金额，需要注意的是：输入交易金额的和应等于输出交易金额的和: ",
        1,
        100,
    );
    let mut output_amount = Vec::with_capacity(output_size as usize);
    loop {
        for i in 1..output_size + 1 {
            output_amount.push(wait_for_number(
                &format!("请为第{}笔输出交易设置金额(1到10000之间的整数)", i),
                1,
                10000,
            ) as u64);
        }

        if input_amount.iter().sum::<u64>() == output_amount.iter().sum() {
            break;
        }

        println_red("输入交易金额的和不等于输出交易金额的和，请重新输入");
        output_amount.clear();
    }

    let mut user_account = Vec::with_capacity(ring_size + output_size);
    for _ in 0..ring_size + output_size {
        user_account.push(Account::new())
    }

    let input_tx: Vec<ConfidentialTransaction> = input_amount
        .iter()
        .map(|x| mint(&user_account[0], *x as u64))
        .collect();

    let decoys_account = &user_account[1..ring_size as usize];
    let mut rng = rand::thread_rng();
    let decoys: Vec<Vec<ConfidentialTransaction>> = decoys_account
        .iter()
        .map(|x| {
            let mut v = Vec::with_capacity(input_size);
            for _ in 0..input_size {
                v.push(mint(x, rng.gen_range(1..10000)));
            }
            v
        })
        .collect();

    let output_account = &user_account[ring_size..ring_size + output_size];
    let output_account: Vec<(Account, u64)> = output_account
        .iter()
        .zip(output_amount.iter())
        .map(|(x, y)| (x.clone(), *y))
        .collect();

    let ring_ct = RingCT {
        ownership_account: user_account[0].clone(),
        output_account: output_account,
        input_tx: input_tx,
        decoys: decoys,
    };

    let mut ring_sig = ring_ct.transfer();
    println!("转账完成，开始验证交易\n");
    assert!(ring_sig.verify());
}

fn mint(admin: &Account, amount: u64) -> ConfidentialTransaction {
    let (one_time_account, blind_pair, symmetric_key) = admin.gen_one_time_account();
    let (token, token_secrt) = Token::mint(amount);
    let encrypto_token_secret = token_secrt.encrypt(&symmetric_key).unwrap();
    let nonnegative_proof = NonnegativeProof::new(&token_secrt);

    ConfidentialTransaction {
        one_time_account: one_time_account,
        blind_point: blind_pair.get_blind_point(),
        token: token,
        nonnegative_proof: nonnegative_proof,
        encrypto_token_secret: encrypto_token_secret,
    }
}

fn println_green(m: &str) {
    println!("{}", m.green())
}

fn println_red(m: &str) {
    println!("{}", m.red())
}

fn wait_for_input() -> String {
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to input.");
    input.trim().to_string()
}

fn wait_for_number(msg: &str, lower: usize, upper: usize) -> usize {
    println_green(msg);
    let mut input = wait_for_input();
    let mut input_num = input.parse::<usize>();
    loop {
        match input_num {
            Ok(v) if v >= lower && v <= upper => return v,
            _ => {
                println_red(msg);
                input = wait_for_input();
                input_num = input.parse::<usize>();
            }
        }
    }
}
