/*
  The merkle tree used in this zkApp.
  As MERKLE_DEPTH = 32, this merkle tree can hold at most 2^32 leaves.
  If you have more than 2^32 items in a tree, please update the MERKLE_DEPTH.
*/

import { Field, MerkleWitness, MerkleTree, Poseidon, PublicKey } from 'o1js';

const MERKLE_DEPTH = 32;

namespace MerkleTreeNamespace {
  export class Witness extends MerkleWitness(MERKLE_DEPTH) {}

  export const indexOf = (leaves: string[], leaf: string): number => {
    const sortedLeaves = leaves.map(each => Poseidon.hash(PublicKey.fromBase58(each).toFields()).toBigInt()).sort((a, b) => {
      if (a < b) return -1;
      if (a > b) return 1;
      return 0;
    });

    const hash = Poseidon.hash(PublicKey.fromBase58(leaf).toFields()).toBigInt();

    return sortedLeaves.indexOf(hash);
  };

  export const createFromFieldArray = (
    leaves: Field[]
  ): MerkleTree | undefined => {
    const tree = new MerkleTree(MERKLE_DEPTH);

    try {
      leaves = leaves.sort((a, b) => {
        if (a.toBigInt() < b.toBigInt()) return -1;
        if (a.toBigInt() > b.toBigInt()) return 1;
        return 0;
      });

      leaves.forEach((leaf, i) => 
        tree.setLeaf(BigInt(i), leaf)
      );

      return tree;
    } catch (err) {
      console.log(err);
      return;
    }
  };

  export const emptyRoot = () => {
    const tree = new MerkleTree(MERKLE_DEPTH);
    return tree.getRoot();
  };
};

export default MerkleTreeNamespace;
