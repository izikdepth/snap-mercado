use snap_coin::full_node::message::{Command, Message};
use snap_coin::full_node::{SharedBlockchain, create_full_node, node_state::SharedNodeState};
use snap_coin_pay::chain_interaction::NodeChainInteraction;
use std::net::SocketAddr;

pub struct ChainInteractor {
    pub blockchain: SharedBlockchain,
    pub node_state: SharedNodeState,
    pub chain_interaction: NodeChainInteraction,
}

impl ChainInteractor {
    pub fn new(node_path: &str) -> Self {
        let (blockchain, node_state) = create_full_node(node_path, false);
        let chain_interaction = NodeChainInteraction::new(node_state.clone(), blockchain.clone());

        Self {
            blockchain,
            node_state,
            chain_interaction,
        }
    }

    // select a peer with the highest blocks
    pub async fn select_peer(&self) -> Option<SocketAddr> {
        let peers = self.node_state.connected_peers.read().await;
        let local_height = self.blockchain.blockstore().get_height();

        let mut best_peer = None;
        let mut best_height = 0u64;

        for (addr, peer) in peers.iter() {
            if let Ok(response) = peer
                .request(Message::new(Command::Ping {
                    height: local_height,
                }))
                .await
            {
                if let Command::Pong { height } = response.command {
                    // Filter peers by whether they're actually ahead of the local node.
                    if height > best_height && height > local_height {
                        best_height = height;
                        best_peer = Some(*addr);
                    }
                }
            }
        }

        best_peer
    }
}
