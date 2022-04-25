use colored::*;
use ct_account::account::Account;
use ct_account::confidential_transaction::ConfidentialTransaction;
use ct_token::prove::NonnegativeProof;
use ct_token::token::*;

fn main() {
    println_green("欢迎来到机密性交易，机密性交易主要保护以下两点：\n 1.交易金额\n 2.接收方地址\n");

    let admin = Account::new();
    let user1 = Account::new();
    let user2 = Account::new();

    let ct = mint(&admin, 1000u64);
    println!(
        "admin mint, balabce:{:?}",
        decrypt_token_secrt(&admin, &ct).balance
    );

    println!("----------------------");
    println!("admin -> user1 : 400");
    let mut sign_tx = ct.transfer(&admin, &user1, 400).unwrap();
    assert!(sign_tx.verify().unwrap());

    let admin_output = &sign_tx.outputs[0];
    let user1_output = &sign_tx.outputs[1];
    println!(
        "admin balabce:{:?}",
        decrypt_token_secrt(&admin, &admin_output).balance
    );
    println!(
        "user1 balabce:{:?}",
        decrypt_token_secrt(&user1, &user1_output).balance
    );

    println!("----------------------");
    println!("admin -> user2 : 100");
    let mut sign_tx = admin_output.transfer(&admin, &user2, 100).unwrap();
    assert!(sign_tx.verify().unwrap());

    let admin_output = &sign_tx.outputs[0];
    let user2_output = &sign_tx.outputs[1];
    println!(
        "admin balabce:{:?}",
        decrypt_token_secrt(&admin, &admin_output).balance
    );
    println!(
        "user2 balabce:{:?}",
        decrypt_token_secrt(&user2, &user2_output).balance
    );

    println!("----------------------");
    println!("user1 -> user2 : 400");
    let mut sign_tx = user1_output.transfer(&user1, &user2, 400).unwrap();
    assert!(sign_tx.verify().unwrap());

    let user1_output = &sign_tx.outputs[0];
    let user2_output = &sign_tx.outputs[1];
    println!(
        "user1 balabce:{:?}",
        decrypt_token_secrt(&user1, &user1_output).balance
    );
    println!(
        "user2 balabce:{:?}",
        decrypt_token_secrt(&user2, &user2_output).balance
    );
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

fn decrypt_token_secrt(account: &Account, ct: &ConfidentialTransaction) -> TokenSecret {
    let key = ct
        .one_time_account
        .get_private_key(account, ct.blind_point)
        .unwrap();
    ct.decrypt_token_secrt(key).unwrap()
}

fn println_green(m: &str) {
    println!("{}", m.green())
}
