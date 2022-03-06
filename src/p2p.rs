use super::{App, Block};
use serde::{Serialize, Deserialize};
use once_cell::sync::{Lazy};
use tokio::sync::{mpsc};
use libp2p::{
    mdns::{Mdns, MdnsEvent},
    swarm::{NetworkBehaviourEventProcess, Swarm},
    floodsub::{Floodsub, FloodsubEvent, Topic},
    identity, PeerId, NetworkBehaviour,
};
use log::{error, info};
use std::collections::{HashSet};

// libp2p client identification params
pub static KEYS: Lazy<identity::Keypair> = Lazy::new(identity::Keypair::generate_ed25519);
pub static PEER_ID: Lazy<PeerId> = Lazy::new(|| PeerId::from(KEYS.public())); // ? -> ||

/**
 * Topic ("channels" to receive/send data):
 *  CHAIN_TOPIC --> Send our local blockchain and receive blockchains from other nodes
 *  BLOCK_TOPIC --> Broadcast and receive new blocks
**/
pub static CHAIN_TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("chains"));
pub static BLOCK_TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("blocks"));

/**
 * Expected struct if we receive a local blockchain, also used
 * to send other nodes our local chain. 
**/
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainResponse {
    pub blocks: Vec<Block>,
    pub receiver: String,
}

/**
 * Triggers ChainResponse. By sending LocalChainRequest with
 * the peer_id of another node in the system, this will trigger
 * that they send us their chain back.
**/
#[derive(Debug, Serialize, Deserialize)]
pub struct LocalChainRequest {
    pub from_peer_id: String
}

/**
 * Used to handle incoming msgs, lazy initialization and
 * keyboard-input (send events across the application to
 * keep the state in sync with incoming/outgoing network traffic).
**/
pub enum EventType {
    LocalChainRequest(ChainResponse),
    Input(String),
    Init,   
}

/**
 * floodsub --> instance for pub/sub communication (https://github.com/libp2p/specs/tree/master/pubsub)
 * mdns --> instance for finding other nodes (https://docs.rs/mdns/latest/mdns/)
 * response_sender / init_sender --> channels for sending events for both req/resp and initialization
 *  communication between parts of the app.
 * app --> App instance 
**/
#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub floodsub: Floodsub,
    pub mdns: Mdns,
    #[behaviour(ignore)]
    pub response_sender: mpsc::UnboundedSender<ChainResponse>,
    #[behaviour(ignore)]
    pub init_sender: mpsc::UnboundedSender<bool>,
    #[behaviour(ignore)]
    pub app: App,
}

impl AppBehaviour {
    pub async fn new(
        app: App,
        response_sender: mpsc::UnboundedSender<ChainResponse>,
        init_sender: mpsc::UnboundedSender<bool>,
    ) -> Self {
        let mut behaviour = Self {
            app,
            floodsub: Floodsub::new(*PEER_ID),
            mdns: Mdns::new(Default::default()).await.expect("Can create mdns"),
            response_sender,
            init_sender
        };
        behaviour.floodsub.subscribe(CHAIN_TOPIC.clone());
        behaviour.floodsub.subscribe(BLOCK_TOPIC.clone());

        behaviour
    }
}

/**
 * If a new node is discovered, we add it to our FloodSub list
 * of nodes for communication. 
**/
impl NetworkBehaviourEventProcess<MdnsEvent> for AppBehaviour {
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer, _addr) in list {
                    self.floodsub.add_node_to_partial_view(peer);
                }
            }
            MdnsEvent::Expired(list) => {
                for (peer, _addr) in list {
                    if !self.mdns.has_node(&peer) {
                        self.floodsub.remove_node_from_partial_view(&peer);
                    }
                }
            }
        }
    }
}

/**
 * Incoming event/msg handler:
 *  - If msg is of type ChainResponse, then we are receiving a
 *    local blockchain by another node. 
 *  - If LocalChainRequest, check peer_id (from request), if it
 *    checks out send our local blockchain.
 *  - If Block, previously mined block sent by node to be verified
 *    and added to our local chain.
**/
impl NetworkBehaviourEventProcess<FloodsubEvent> for AppBehaviour {
    fn inject_event(&mut self, event: FloodsubEvent) {
        if let FloodsubEvent::Message(msg) = event {
            if let Ok(resp) = serde_json::from_slice::<ChainResponse>(&msg.data) {
                if resp.receiver == PEER_ID.to_string() {
                    info!("Response from: {}", msg.source);
                    resp.blocks.iter().for_each(|r| info!("{:?}", r));

                    self.app.blocks = self.app.choose_chain(self.app.blocks.clone(), resp.blocks);
                }
            } else if let Ok(resp) = serde_json::from_slice::<LocalChainRequest>(&msg.data) {
                if resp.from_peer_id == PEER_ID.to_string() {
                    info!("Sending local chain to {}", msg.source.to_string());
                    if let Err(e) = self.response_sender.send(ChainResponse {
                        blocks: self.app.blocks.clone(),
                        receiver: msg.source.to_string(),
                    }) {
                        error!("Error sending response via channel, {}", e);
                    }
                }
            } else if let Ok(block) = serde_json::from_slice::<Block>(&msg.data) {
                info!("received new block from: {}", msg.source.to_string());
                self.app.add_block(block);
            }
        }
    }
}

pub fn get_list_peers(swarm: &Swarm<AppBehaviour>) -> Vec<String> {
    info!("Peers: ");
    let nodes = swarm.behaviour().mdns.discovered_nodes();
    let mut unique_peers = HashSet::new();
    for peer in nodes {
        unique_peers.insert(peer);
    }
    unique_peers.iter().map(|p| p.to_string()).collect()
}

pub fn print_peers(swarm: &Swarm<AppBehaviour>) {
    let peers = get_list_peers(swarm);
    peers.iter().for_each(|p| info!("{}", p));
}

pub fn print_chain(swarm: &Swarm<AppBehaviour>) {
    info!("Local Blockchain:");
    let json = serde_json::to_string_pretty(&swarm.behaviour().app.blocks).expect("jsonify blocks");
    info!("{}", json)
}

pub fn create_block(cmd: &str, swarm: &mut Swarm<AppBehaviour>) {
    if let Some(data) = cmd.strip_prefix("create b") {
        let behaviour = swarm.behaviour_mut();
        let latest_block = behaviour
            .app
            .blocks
            .last()
            .expect("at least one block");
        // Create and mine new block
        let block = Block::new(
            latest_block.id + 1,
            latest_block.hash.clone(),
            data.to_owned(),
        );
        let json = serde_json::to_string(&block).expect("jsonify block");
        behaviour.app.blocks.push(block);
        info!("Broadcasting new block");
        behaviour
            .floodsub
            .publish(BLOCK_TOPIC.clone(), json.as_bytes());
    }
}