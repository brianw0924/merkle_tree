#![allow(dead_code)]
#![allow(unused_variables)]

use sha2::Digest;
use std::collections::HashMap;

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;


pub struct MerkleTree {
    pub nodes: Vec<Vec<Data>>,
    pub leaves_idx: HashMap<Hash, usize>,
}


// Which side to put Hash on when concatinating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}


#[derive(Debug, Default)]
pub struct Proof<'a> {
    // The hashes to use when verifying the proof
    // The first element of the tuple is which side the hash should be on when concatinating
    hashes: Vec<(HashDirection, &'a Hash)>,
}


impl MerkleTree {
    // Gets root hash for this tree
    pub fn root(&self) -> Hash {
        // todo!("For tests to work")
        self.nodes.last().unwrap().get(0).unwrap().clone()
    }


    // Constructs a Merkle tree from given input data
    pub fn construct(input: &[Data]) -> MerkleTree {
        // Store nodes at each level
        let mut nodes = Vec::new();

        // Fast access to leaves
        let mut leaves_idx = HashMap::with_capacity(input.len());
        
        // Preprocess the input to hashes
        let mut new_nodes: Vec<Hash> = input.iter().enumerate().map(|(i, leaf)| {
            let h = hash_data(leaf);
            leaves_idx.insert(h.clone(), i);
            h
        }).collect();

        // Keep reducing the nodes util only root left 
        while new_nodes.len() > 1 {
            nodes.push(new_nodes.clone());
            new_nodes = new_nodes
                .chunks(2)
                .map(|chunk| {
                    if chunk.len() == 1 {
                        chunk[0].clone()
                    } else {
                        hash_concat(&chunk[0], &chunk[1])
                    }
                })
                .collect();
        }
        // Push the root
        nodes.push(new_nodes);

        MerkleTree {
            nodes,
            leaves_idx,
        }
    }

    // Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {

        if input.is_empty() {
            root_hash.is_empty()
        } else {
            // Just calculate the root_hash, don't need to store nodes
            let mut nodes: Vec<Hash> = input.iter().map(|data| hash_data(data)).collect();
            while nodes.len() > 1 {
                nodes = nodes
                    .chunks(2)
                    .map(|chunk| {
                        if chunk.len() == 1 {
                            chunk[0].clone()
                        } else {
                            hash_concat(&chunk[0], &chunk[1])
                        }
                    }).collect();
            }
            nodes[0] == *root_hash
        }
    }


    // Verifies that the given data and proof_path correctly produce the given root_hash
    pub fn verify_proof(data: &Data, proof: &Proof, root_hash: &Hash) -> bool {
        let mut current_hash = hash_data(data);
        for (hash_direction, hash) in proof.hashes.iter() {
            current_hash = match hash_direction {
                HashDirection::Left => hash_concat(*hash, &current_hash),
                HashDirection::Right => hash_concat(&current_hash, *hash),
            };
        }
        current_hash == *root_hash
    }


    // Returns a list of hashes that can be used to prove that the given data is in this tree
    pub fn prove(&self, data: &Data) -> Option<Proof> {
        if let Some(mut current_idx) = self.leaves_idx.get(&hash_data(data)).copied() {
            let mut hashes = Vec::new();

            for level in 0..self.nodes.len()-1 {
                let parent_idx = current_idx / 2;
                if current_idx % 2 == 0 {
                    // Only push node if exist
                    if let Some(neighbor_hash) = self.nodes[level].get(current_idx+1) {
                        hashes.push((HashDirection::Right, neighbor_hash));
                    }
                } else {
                    hashes.push((HashDirection::Left, &self.nodes[level][current_idx-1]));
                }
                current_idx = parent_idx;
            }
            Some(Proof { hashes })
        } else {
            None
        }
    }
}


fn hash_data(data: &Data) -> Hash {
    sha2::Sha256::digest(data).to_vec()
}


fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}


#[cfg(test)]
mod tests {
    use super::*;


    fn example_data(n: usize) -> Vec<Data> {
        let mut data = vec![];
        for i in 0..n {
            data.push(vec![i as u8]);
        }
        data
    }

    #[test]
    fn test_construct_root() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let expected_root = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";
        assert_eq!(hex::encode(tree.root()), expected_root);

        // Uncomment if your implementation allows for unbalanced trees
        let data = example_data(3);
        let tree = MerkleTree::construct(&data);
        let expected_root = "773a93ac37ea78b3f14ac31872c83886b0a0f1fec562c4e848e023c889c2ce9f";
        assert_eq!(hex::encode(tree.root()), expected_root);

        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let expected_root = "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578";
        assert_eq!(hex::encode(tree.root()), expected_root);
    }

    #[test]
    fn test_verify() {
        for n in 1..=10 {
            let data = example_data(n);
            let tree = MerkleTree::construct(&data);
            assert_eq!(MerkleTree::verify(&data, &tree.root()), true);
        }
        assert_eq!(MerkleTree::verify(&vec![], &vec![]), true);
        assert_eq!(MerkleTree::verify(&vec![vec![0u8]], &vec![]), false);
        assert_eq!(MerkleTree::verify(&vec![], &hash_data(&vec![0u8])), false);
    }

    #[test]
    fn test_verify_proof() {
        for n in 1..=10 {
            let data = example_data(n);
            let tree = MerkleTree::construct(&data);
            for m in 0..n {
                let proof = tree.prove(&data[m]);
                assert!(proof.is_some());
                assert_eq!(MerkleTree::verify_proof(&data[m], &proof.unwrap(), &tree.root()), true);
            }
            let fake_data = vec![(n+1) as u8];
            let proof = tree.prove(&fake_data);
            assert!(proof.is_none());
        }
    }
}
