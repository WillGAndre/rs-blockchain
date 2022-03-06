use chrono::prelude::*;
use libp2p::{
    core::upgrade,
    futures::StreamExt,
    mplex,
    noise::{Keypair, NoiseConfig, X25519Spec},
    swarm::{Swarm, SwarmBuilder},
    tcp::TokioTcpConfig,
    Transport,
};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::{
    io::{stdin, AsyncBufReadExt, BufReader},
    select, spawn,
    sync::mpsc,
    time::sleep,
};

mod p2p;

/**
 * Hash (of data in block) must start with 00.
 *  \
 *   -> Network attribute: agreed upon between nodes
 *      based on a consensus algorithm.
**/
const DIFFICULTY_PREFIX: &str = "00";

pub struct App {
    pub blocks: Vec<Block>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub id: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp: i64,
    pub data: String,
    pub nonce: u64,
}

/**
 * Helper Function: 
 *  Binary representation of a given byte array 
 *  in the form of a String.
 **/
fn hash_to_binary(hash: &[u8]) -> String {
    let mut res: String = String::default();
    for c in hash {
        res.push_str(&format!("{:b}", c));
    }
    res
}

fn calc_hash(id: u64, timestamp: i64, prev_hash: &str, data: &str, nonce: u64) -> Vec<u8> {
    let data = serde_json::json!({
        "id": id,
        "prev_hash": prev_hash,
        "data": data,
        "timestamp": timestamp,
        "nonce": nonce
    });
    let mut hasher = Sha256::new();
    hasher.update(data.to_string().as_bytes());
    hasher.finalize().as_slice().to_owned()
}

/**
 * Mining:
 *  From block data and nonce generate hash
 *  that starts with our difficulty prefix.
**/
fn mine_block(id: u64, timestamp: i64, prev_hash: &str, data: &str) -> (u64, String) {
    info!("mining block");
    let mut nonce = 0;

    loop {
        if nonce % 100000 == 0 {
            info!("nonce: {}", nonce);
        }
        let hash = calc_hash(id, timestamp, prev_hash, data, nonce);
        let bin_hash = hash_to_binary(&hash);
        if bin_hash.starts_with(DIFFICULTY_PREFIX) {
            let hex_hash = hex::encode(&hash);
            info!("mined nonce: {}, hash: {}, bin hash: {}",
                nonce, hex_hash, bin_hash
            );
            return (nonce, hex_hash);
        }
        nonce += 1;
    }
}

/**
 * Simple consensus criteria:
 *  Ask other nodes for their chains, if 
 *  there is any longer than ours, use theirs.
**/
impl App {
    fn new() -> Self {
        Self { blocks: vec![] }
    }

    fn genesis(&mut self) {
        let genesis_block = Block {
            id: 0,
            timestamp: Utc::now().timestamp(),
            prev_hash: String::from("none"),
            data: String::from("genesis_block"),
            nonce: 2836,
            hash: "0000f816a87f806bb0073dcf026a64fb40c946b5abee2573702828694d5b4c43".to_string(),
        };
        self.blocks.push(genesis_block);
    }

    fn add_block(&mut self, block: Block) {
        let prev_block = self.blocks.last().expect("At least one block");
        if self.is_block_valid(&block, prev_block) {
            self.blocks.push(block);
        } else {
            error!("unable to add block - invalid");
        }
    }

    fn is_block_valid(&self, block: &Block, prev_block: &Block) -> bool {
        if block.prev_hash != prev_block.hash {
            warn!("Block with id: {} has incorrect previous hash", block.id);
            return false;
        } else if !hash_to_binary(&hex::decode(&block.hash).expect("Decodable hex")).starts_with(DIFFICULTY_PREFIX) {
            warn!("Block with id: {} has invalid difficulty", block.id);
            return false;
        } else if block.id != prev_block.id + 1 {
            warn!(
                "Block with id: {} is not the next block after the latest: {}",
                block.id,
                prev_block.id
            );
            return false;
        } else if hex::encode(calc_hash(
            block.id,
            block.timestamp,
            &block.prev_hash,
            &block.data,
            block.nonce,
        )) != block.hash {
            warn!("Block with id: {} has invalid hash", block.id);
            return false;
        }
        true
    }

    fn is_chain_valid(&self, chain: &[Block]) -> bool {
        for i in 0..chain.len() {
            if i == 0 {
                continue;
            }
            let prev_block = chain.get(i - 1).expect("Block must exist");
            let block = chain.get(i).expect("Block must exist");
            if !self.is_block_valid(block, prev_block) {
                return false;
            }
        }
        true
    }

    fn choose_chain(&self, local: Vec<Block>, remote: Vec<Block>) -> Vec<Block> {
        let is_local_valid = self.is_chain_valid(&local);
        let is_remote_valid = self.is_chain_valid(&remote);

        if is_local_valid && is_remote_valid {
            if local.len() >= remote.len() {
                local
            } else {
                remote
            }
        } else if is_local_valid && !is_remote_valid {
            local
        } else if !is_local_valid && is_remote_valid {
            remote
        } else {
            panic!("Local and remote chains both invalid");
        }
    }
}

impl Block {
    pub fn new(id: u64, prev_hash: String, data: String) -> Self {
        let now = Utc::now();
        let (nonce, hash) = mine_block(id, now.timestamp(), &prev_hash, &data);
        Self {
            id,
            hash,
            timestamp: now.timestamp(),
            prev_hash,
            data,
            nonce,
        }
    }
}

// TODO: Switch edition to 2021
/**
 *  
**/
#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    
    info!("Peer ID: {}", p2p::PEER_ID.clone());
    // App channels
    let (response_sender, mut response_rcv) = mpsc::unbounded_channel(); // ignore type error
    let (init_sender, mut init_rcv) = mpsc::unbounded_channel();
    // Gen X25519 (elliptic curve DH key exchange) key pair
    let auth_keys = Keypair::<X25519Spec>::new()
        .into_authentic(&p2p::KEYS)
        .expect("Auth keys created");
    // libp2p transport
    let transp = TokioTcpConfig::new()
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(auth_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();
    // Init App behaviour
    let behaviour = p2p::AppBehaviour::new(
        App::new(), 
        response_sender, 
        init_sender.clone()
    ).await;
    // Init Swarm (controls/runs network stack)
    let mut swarm = SwarmBuilder::new(transp, behaviour, *p2p::PEER_ID)
        .executor(Box::new(|fut| {
            spawn(fut);
        })).build();
    let mut stdin = BufReader::new(stdin()).lines();
    
    Swarm::listen_on(
        &mut swarm,
        "/ip4/0.0.0.0/tcp/0".parse().expect("can get local socket"),
    ).expect("swarm created");

    // init node (sleep) and ask another node for current blockchain
    spawn(async move {
        sleep(Duration::from_secs(1)).await;
        info!("init event");
        init_sender.send(true).expect("init event");
    });

    // select! --> macro to race multiple async functions
    loop {
        // Create events, swarm events aren't handled by Mdns or Floodsub so they are simply logged in.
        let evt = {
            select! {
                line = stdin.next_line() => Some(p2p::EventType::Input(line.expect("get line").expect("line from stdin"))),
                res = response_rcv.recv() => {
                    Some(p2p::EventType::LocalChainRequest(res.expect("response exists")))
                },
                _init = init_rcv.recv() => {
                    Some(p2p::EventType::Init)
                },
                event = swarm.select_next_some() => {
                    info!("Unhandled swarm event {:?}", event);
                    None
                },
            }
        };

        // After event creation, handle them
        if let Some(event) = evt {
            match event {
                // Init Event:
                //  Create genesis block and if connected 
                //  to nodes trigger LastChainRequest to last peer.
                p2p::EventType::Init => {
                    let peers = p2p::get_list_peers(&swarm);
                    swarm.behaviour_mut().app.genesis();

                    info!("Total connected nodes: {}", peers.len());
                    if !peers.is_empty() {
                        let req = p2p::LocalChainRequest {
                            from_peer_id: peers.iter()
                                .last()
                                .expect("peer")
                                .to_string(),
                        };
                        let json = serde_json::to_string(&req).expect("jsonify request");
                        swarm
                            .behaviour_mut()
                            .floodsub
                            .publish(p2p::CHAIN_TOPIC.clone(), json.as_bytes());
                    }
                },
                // LocalChainRequest event:
                //  Send incoming msg/json to FloodSub topic since
                //  our FloodSub impl handles this event (by broadcasting to all nodes).
                p2p::EventType::LocalChainRequest(resp) => {
                    let json = serde_json::to_string(&resp).expect("jsonify response");
                    swarm
                        .behaviour_mut()
                        .floodsub
                        .publish(p2p::CHAIN_TOPIC.clone(), json.as_bytes());
                },
                // User input events:
                //  ls p --> print peers
                //  ls c --> print local blockchain 
                //  create b <data> --> creates new block with <data> (str)
                p2p::EventType::Input(line) => match line.as_str() {
                    "ls p" => p2p::print_peers(&swarm),
                    cmd if cmd.starts_with("ls c") => p2p::print_chain(&swarm),
                    cmd if cmd.starts_with("create b") => p2p::create_block(cmd, &mut swarm),
                    _ => error!("Unkown command"),
                },
            }
        }
    };
}   
