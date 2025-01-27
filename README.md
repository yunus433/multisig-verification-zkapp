# o1js MultiSig Verification zkApp Example

This is an example zkApp showing how to implement and use a MultiSig verification in o1js to create a bridge or a decentralized oracle. By reading through this README, you can understand how to implement a MultiSig verification in your o1js application.

**Important**: Please note that this zkApp does not implement a cryptographic MultiSig algorithm, but a ZKP (Zero Knowledge Proof) designed to achieve the same as a cryptographic MultiSig.

## Contents

1. Background and Motivation
2. The Verification Process of an Off-Chain Data
3. Zero Knowledge Proof Design for a MultiSig
4. Performance and Security
5. Possible Future Updates
6. Conclusion

## Background and Motivation

In blockchains, accessing off-chain data is crucial. (By off-chain data, we refer to any data that does not exist in that particular blockchain, either from the regular Web2 or from another blockchain.) Some examples may be the price of a decentralized or regular asset, some credential from a governemental authority (like a passport), the number of posts that an account has on a social media platform, the current block height in another blockchain etc. It is of course possible to get this data directly from the source and post it on the target chain as a decentralized TX to a smart contract. However, as this TX is sent by a single person, it can easily be changed (i.e. it is centralized). In order to avoid this centralization, we need a way to put this data on the chain decentralizely.

**Note**: Commonly, a decentralized passage of information from another blockchain is named as a _bridge_, and from a Web2 source as an _oracle_. Technically, there is usually not too much difference.

While implementing a decentralized bridge or an oracle, one of the most commonly used methods is multiple signature verification (a.k.a. **MultiSig Verification**). This method is basically using a set of nodes (similar to miners in PoW or validators in PoS) to verify the integrity of the data. These nodes (called hereafter as **Signer Nodes**) are responsible for verifying the data (either by connecting to the other blockchain or to the Web2 source) and signing its hash with their private key. (Usually we make a 51% or 66% honesty assumption over this set by using a method like PoS). Then, we assume that any information signed by the honest majority of the set (like 66%) is _trustable_ in a decentralized sense. As a result, this method can be used to create bridges between different blockchains or trustless oracles to Web2 sources.

This project is not to design an economically secure Signer Node set, but rather it is to show how the signature verification aspect of such a set can be achieved in o1js / Mina as a ZKP: Because of its unique design as a Succinct ZK L1, Mina does not perform signature verification like other blockchains. This forces us to create a unique architectural model around Mina's structure.

In this repository, you will find:

- An o1js ZKP for aggregating multiple o1js Signatures together,
- An example Mina contract for the settlement process of this MultiSig proof,
- An aggregation ZKP to update the settlement contract with multiple MultiSig proof at one TX (detailed later),
- BONUS: The design and implement of updating the Signer Node set.

## The Verification Process of an Off-Chain Data

**Important**: Mina smart contracts have a very limited storage capacity (i.e. on-chain storage). Specifically, each Mina zkApp can have at most 8 `Field` elements (i.e. 32 bytes). This makes impossible to store a data on Mina as it is. Thus, we need to store the **commitment** of this data, meaning a constant sized information allowing the verification of the data (e.g. a [hash](https://en.wikipedia.org/wiki/Hash_function) or a [merkle root](https://en.wikipedia.org/wiki/Merkle_tree)).

Assume that you are hosting a decentralized oracle service on Mina. Your service allows users to submit a verification request for a custom API online. They tell you the URL of this API and ask you to put a commitment of the data stored in this API, so that they can use this data in their zkApp while proving its integrity. Let us go through each step during this interaction.

### 1) The user submits a verification request

First, the user needs to let your service know that they need the verification of some data on an API, so they send you a request. An example format of this request may be:

```json
{
  "url": "https://api.minaexplorer.com",
  "route": "/blocks/3NKxeCQcdESLhYNAC3BHpQtS4QVtr8D5M8FvbQfostRq3tCuzptw/",
  "field": "creatorAccount.publicKey"
}
```

This request basically tells us to go to the domain `https://api.minaexplorer.com/blocks/3NKxeCQcdESLhYNAC3BHpQtS4QVtr8D5M8FvbQfostRq3tCuzptw` and get the field `creatorAccount.publicKey`, which is (at the time of writing of this article) `B62qjvx1gE8xJ3H9Wx5JTx4GcCEanEjUK3MFWZjaGu7hLUr18UUXbWL`.

Here, the request is made to a regular Web2 server over an internet port, which named hereafter as the **Verifier Node**. It is of course possible to use the Mina blockchain's gossip network for this request, but as the Verifier Node has always the right to reject the verification of a data, using the gossip network does not increase the censorship resistance of the system, so it an unnecessary usage of on-chain resources.

### 2) The user makes a payment for the verification request (optional)

You can of course design your system to verify anything without asking for a fee, but most of time this is not the case, and we need to ask for a payment in return of the verification service we provide. Ideally, it is preferable to get this payment over the Mina Blockchain as MINA, but unfortunately Mina has a limited TX capacity and a low block time, so it is not really scalable to get payments only on Mina.

As a result, we do not implement a payment system on this example zkApp. In your Verifier Node implementation, you can chose any method of authentication to allow people access your API service. This is identical to any Web2 REST API.

### 3) The Verifier Node asks for signatures of the Signer Node Set

As explained before, in order to achieve the decentralized verification of an off-chain data, we need a Signer Node Set with an economical security guarantee. Assuming that we have already this set and there are `N` Signers in the Signer Node Set. Each Signer has a unique `PublicKey` and a known URL (so that we can send requests to them).

On Mina, the Verifier Node has a zkApp used for the storage of commitments of verification requests. The zkApp stores the following data on the state:

```ts
{
  "owner": PublicKey, // This is the PublicKey of the Verifier Node
  "signerNodeSetMerkleRoot": Field, // The merkle root storing signer nodes. This does not change in time.
  "signerNodeCount": Field, // Number of signer nodes
  "commitmentsMerkleRoot": Field // The merkle root storing commitments, controlled by the Verifier Node
}
```

The `owner` state assures that it is always the Verifier interacting with this smart contract. Upon request, this contract can be made permissionless by removing the `owner` state, but it is not recommended.

### Method 1: Direct Signature Verification on the Smart Contract