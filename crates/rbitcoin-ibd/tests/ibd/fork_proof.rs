use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Witness, Work,
};
use rbitcoin_ibd::ibd::fork_proof::{prefix_beating, ForkProofs, MAX_BYTES};

/// A regtest block on `prev` whose coinbase names `salt`, with `pad` extra
/// bytes in its output script.
fn block(prev: BlockHash, salt: u32, pad: usize) -> Block {
    let coinbase = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(salt.to_le_bytes().to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a; pad]),
        }],
    };
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_600_000_000 + salt,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    block
}

fn chain(from: BlockHash, n: u32, salt: u32, pad: usize) -> Vec<Block> {
    let mut out: Vec<Block> = Vec::new();
    for i in 0..n {
        let prev = out.last().map_or(from, |b| b.block_hash());
        out.push(block(prev, salt + i, pad));
    }
    out
}

fn headers(blocks: &[Block]) -> Vec<Header> {
    blocks.iter().map(|b| b.header).collect()
}

fn wire(b: &Block) -> Vec<u8> {
    bitcoin::consensus::encode::serialize(b)
}

fn work(blocks: &[Block]) -> Work {
    blocks
        .iter()
        .fold(Work::from_be_bytes([0; 32]), |w, b| w + b.header.work())
}

/// The shortest prefix that beats the given work, and none when the whole
/// chain does not.
#[test]
fn the_prefix_to_prove_is_the_shortest_that_beats_this_nodes_data() {
    let fork = chain(BlockHash::all_zeros(), 5, 1, 0);
    let one = fork[0].header.work();
    assert_eq!(
        prefix_beating(&headers(&fork), Work::from_be_bytes([0; 32])),
        Some(1)
    );
    assert_eq!(prefix_beating(&headers(&fork), one), Some(2));
    assert_eq!(prefix_beating(&headers(&fork), work(&fork[..4])), Some(5));
    assert_eq!(prefix_beating(&headers(&fork), work(&fork)), None);
}

/// Only the prefix block a header names, with the transactions it commits
/// to, is kept. A heavier fork whose blocks are withheld does not stop a
/// lighter one that is served from being handed back, and a third fork
/// drops the lightest.
#[test]
fn a_served_fork_is_handed_back_and_a_withheld_one_waits() {
    let root = BlockHash::all_zeros();
    let heavy = chain(root, 4, 100, 0);
    let light = chain(root, 3, 200, 0);
    let mut proofs = ForkProofs::default();
    proofs.offer(root, 0, &headers(&heavy), 2, work(&heavy), Some(1));
    proofs.offer(root, 0, &headers(&light), 2, work(&light), Some(2));
    assert_eq!(proofs.wanted().len(), 4);
    assert_eq!(
        proofs.wanted()[0].hash,
        heavy[0].block_hash(),
        "heaviest first"
    );
    assert_eq!(proofs.wanted()[0].peer, Some(1));

    let mut wrong = light[0].clone();
    wrong.txdata[0].lock_time = LockTime::from_consensus(7);
    assert!(
        !proofs.accept(light[0].block_hash(), wire(&wrong)),
        "not that block"
    );
    assert!(!proofs.accept(light[0].block_hash(), Vec::new()));
    assert!(
        !proofs.accept(light[2].block_hash(), wire(&light[2])),
        "past the prefix"
    );
    assert!(proofs.accept(light[0].block_hash(), wire(&light[0])));
    assert!(proofs.take_ready().is_none(), "half a prefix");
    assert!(proofs.accept(light[1].block_hash(), wire(&light[1])));
    assert!(proofs.is_proven(root, &headers(&light), 2));
    assert!(!proofs.is_proven(root, &headers(&heavy), 2));
    let (peer, fork, handed) = proofs.take_ready().expect("the served fork");
    assert_eq!((peer, fork), (Some(2), root));
    assert_eq!(handed, headers(&light));
    assert!(proofs.take_ready().is_none(), "handed back once");

    let third = chain(root, 5, 300, 0);
    proofs.offer(root, 0, &headers(&third), 2, work(&third), Some(3));
    assert!(
        !proofs
            .wanted()
            .iter()
            .any(|w| w.hash == light[0].block_hash()),
        "the lightest fork made room"
    );
    assert_eq!(proofs.bytes(), 0, "its bodies went with it");
}

/// Served bodies count against one cap until the path takes them.
#[test]
fn served_bodies_are_capped_and_freed_when_taken() {
    let root = BlockHash::all_zeros();
    let big = (MAX_BYTES / 2) as usize;
    let fork = chain(root, 3, 400, big);
    let mut proofs = ForkProofs::default();
    proofs.offer(root, 0, &headers(&fork), 3, work(&fork), Some(1));
    assert!(proofs.accept(fork[0].block_hash(), wire(&fork[0])));
    let held = proofs.bytes();
    assert_eq!(held, wire(&fork[0]).len() as u64);
    assert!(
        !proofs.accept(fork[1].block_hash(), wire(&fork[1])),
        "past the cap"
    );
    assert!(proofs.wants(&fork[1].block_hash()), "still wanted");
    assert_eq!(
        proofs.take_body(&fork[0].block_hash()),
        Some(wire(&fork[0]))
    );
    assert_eq!(proofs.bytes(), 0);
    assert!(proofs.accept(fork[1].block_hash(), wire(&fork[1])));
}
