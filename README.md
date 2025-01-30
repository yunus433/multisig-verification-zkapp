# o1js MultiSig Verification zkApp Example

This is an example zkApp showing how to implement and use a MultiSig verification in o1js to create a bridge or a decentralized oracle. By reading through this README, you can understand how to implement a MultiSig verification zkApp as an o1js application on top of the Mina Protocol.

**Warning**: This article assumes that the reader is already familiar with the basic concepts of o1js and the Mina Protocol. For more introductory information, you can refer to the official [Mina & o1js Documentation](https://docs.minaprotocol.com/).

**Important**: Please note that this zkApp does not implement a cryptographic MultiSig algorithm, but a ZKP (Zero Knowledge Proof) designed to achieve the same as a cryptographic MultiSig.

## Contents

1. Background and Motivation
2. The Verification Process of an Off-Chain Data
3. Conclusion

## Background and Motivation

In blockchains, accessing off-chain data is crucial. (By off-chain data, we refer to any data that does not exist in that particular blockchain, either from the regular Web2 or from another blockchain.) Some examples may be the price of a decentralized or regular asset, some credential from a governmental authority (like a passport), the number of posts that an account has on a social media platform, the current block height in another blockchain etc. It is of course possible to get this data directly from the source and post it on the target chain as a decentralized TX to a smart contract. However, as this TX is sent by a single person, it can easily be changed (i.e. it is centralized). In order to avoid this centralization, we need a way to put this data on the chain in a decentralized manner.

**Note**: Commonly, a decentralized passage of information from another blockchain is named as a _bridge_, and from a Web2 source as an _oracle_. Technically, there are not too much difference.

While implementing a decentralized bridge or an oracle, one of the most commonly used methods is multiple signature verification (a.k.a. **MultiSig Verification**). This method is basically using a set of nodes (similar to miners in PoW or validators in PoS) to verify the integrity of the data. These nodes (called hereafter as **Signer Nodes**) are responsible for verifying the data (either by connecting to the other blockchain or to the Web2 source) and signing its hash with their private key. (Usually we make a 51% or 66% honesty assumption over this set by using a method like PoS). Then, we assume that any information signed by the honest majority of the set (like 66%) is _trustable_ in a decentralized sense. As a result, this method can be used to create bridges between different blockchains or trustless oracles to Web2 sources.

This project is not to design an economically secure Signer Node set, but rather it is to show how the signature verification aspect of such a set can be achieved in o1js / Mina as a ZKP: Because of its unique design as a Succinct ZK L1, Mina does not perform signature verification like other blockchains. This forces us to create a unique architectural model around Mina's structure.

In this repository, you will find:

- An o1js ZKP for aggregating multiple o1js Signatures together,
- An example Mina contract for the settlement process of this MultiSig proof,
- An aggregation ZKP to update the settlement contract with multiple MultiSig proof at one TX,
- Examples of Signer and Verifier Nodes to show how to use the above functionality.
- Extra: The design and implementation of add / remove functions for the signers in the Signer Node set.

## The Verification Process of an Off-Chain Data

Assume that you are hosting a decentralized oracle service on Mina. Your service allows users to submit a verification request for a custom API online. They tell you the URL of this API and ask you to put a _commitment_ of the data stored in this API, so that they can use this data in their zkApp while proving its integrity.

**Important**: Mina smart contracts have a very limited storage capacity (i.e. on-chain storage). Specifically, each Mina zkApp can have at most 8 `Field` elements (i.e. 32 bytes). This makes impossible to store a data on Mina as it is. Thus, we need to store the **commitment** of this data, meaning a constant sized information allowing the verification of the data (e.g. a [hash](https://en.wikipedia.org/wiki/Hash_function) or a [merkle root](https://en.wikipedia.org/wiki/Merkle_tree)). In this implementation, we use a [Merkle Map](https://docs.minaprotocol.com/zkapps/tutorials/common-types-and-functions#merkle-map).

Let us go through each step of the interaction between a User and the decentralized oracle service.

**Note**: You can find a Pseudo-Code like implementation of the verification functionality of such a service [here](./src/example/verification.ts).

### 1) The User submits a verification request

First, the User needs to let your service know that they need the verification of some data on an API, so they send you a request. An example format of this request may be:

```json
{
  "url": "https://api.minaexplorer.com",
  "route": "/blocks/3NKxeCQcdESLhYNAC3BHpQtS4QVtr8D5M8FvbQfostRq3tCuzptw/",
  "field": "creatorAccount.publicKey"
}
```

This request basically tells us to go to the domain `https://api.minaexplorer.com/blocks/3NKxeCQcdESLhYNAC3BHpQtS4QVtr8D5M8FvbQfostRq3tCuzptw` and get the field `creatorAccount.publicKey`, which equals to (at the time of writing of this article) `B62qjvx1gE8xJ3H9Wx5JTx4GcCEanEjUK3MFWZjaGu7hLUr18UUXbWL`.

Here, the request is made to a regular Web2 server over an internet port, which named hereafter as the **Verifier Node**. It is of course possible to use the Mina blockchain's gossip network for this request, but as the Verifier Node has always the right to reject the verification of a data, using the gossip network does not increase the censorship resistance of the system, so it an unnecessary usage of on-chain resources.

### 2) The User makes a payment for the verification request (optional)

You can of course design your system to verify anything without asking for a fee, but most of time this is not the case, and we need to ask for a payment in return of the verification service we provide. Ideally, it is preferable to get this payment over the Mina Blockchain as MINA, but unfortunately Mina has a limited TX capacity and a low block time, so it is not really scalable to get payments only on Mina.

As a result, we do not implement a payment system on this example zkApp. In your Verifier Node implementation, you can chose any method of authentication to allow people access your API service. This is identical to any Web2 REST API.

### 3) The Verifier Node asks for signatures of the Signer Node Set

As explained before, in order to achieve the decentralized verification of an off-chain data, we need a Signer Node Set with an economical security guarantee. Let's assume that we have already this set with `N` Signer Nodes with a proper economical security model so that anything signed by more than 66% of this set is accepted as true in the MultiSig zkApp. Each Signer has a unique `PublicKey` and a known URL (so that we can send requests to them). Additionally, each signer knows the `PublicKey` of the Verifier Node, so that they can validate requests coming from the Verifier Node.

There are multiple ways to make all Signer Nodes know about the signature request. Here, we adapt the most basic model, where the Verifier Node requests for the signature of each Signer Node with the following format:

```json
{
  "signature": "Signature of hash of the data by the Verifier Node's PrivateKey",
  "data": {
    "url": "URL of the request",
    "route": "Route of the request",
    "field": "Field of the request"
  }
}
```

### 4) Each Signer Node creates a signature with their PrivateKey for the given data

After receiving the signature request, Signer Nodes first verify the request signature to make sure its validity. (Signer Nodes only accept signature requests coming from their Verified Node to avoid DDoDs like attacks.) Then, they go to the given URL, get the defined route and read the requested field. We will be naming the information available in this field as **data** hereafter.

The received data can have any type (e.g. `number`, `string`, `boolean`, `object`, etc.). In order to create a `Signature` over it, Signer Nodes need to convert it to a Provable Type, like a `Field`. This conversion is crucial, as it must be followed by the User in order to use the commitment afterwards.

**Important**: Converting a `number` or `boolean` to a provable type is trivial, and for converting a `string` you can use the given `stringToFieldArray()` function in the [utils](/src/lib/utils.ts) file. Please note that this function is given as an example, and it is the safest for you to reimplement it based on your needs.

As an example, the Signer Node can run the code in this [file](./src/example/signer.ts) in the case we expect the data to be of type `number`.

### 5) Verifier Node aggregates all signatures together.

Once it has signatures of 66% of the Signer Node set, the Verifier Node can add the commitment of the requested data on chain. However, it needs a way to combine all these signatures together while verifying that:

1. Each signature is valid : `Signature.verify(SIGNER_PUBLIC_KEY, [ dataToSign ])`
2. Each signature is unique.

Here, we do not detail how this **MultiSig ZKP** is implemented, but you can assume that it performs this functionality and outputs the total number of valid signatures in a list of signatures. For more details, you can inspect the code [here](./src/aggregation/SignatureAggregation.ts).

Once aggregated, we now have a single ZKP that we can use for settlement.

### 6) Verifier Node settles the given data and returns the witness of commitment

As it provides a decentralized oracle service, the Verifier Node has a zkApp used for the storage of commitments of verification requests. This zkApp is named as the **Settlement Contract**, as the Verifier settles the result of the proof as an update on the commitment (i.e. the merkle map root) without using any on-chain computation.

This Settlement Contract (implemented [here](./src/contract/Settlement.ts)) stores the following data on the state:

```ts
{
  "verifier": PublicKey, // This is the PublicKey of the Verifier Node
  "signersTreeRoot": Field, // The merkle root storing signer nodes. This does not change in time.
  "signersCount": Field, // Number of signer nodes
  "verifiedDataTreeRoot": Field // The merkle root storing commitments, controlled by the Verifier Node
}
```

The `verifier` state assures that it is always the Verifier interacting with this smart contract. Upon request, this contract can be made permissionless by removing the `verifier` state, but it is not recommended.

By calling the `settle()` function, the Verifier updates the commitment.

Finally, in order for the User to interact with the settled commitment, the Verifier returns the witness of this commitment.

### 7) User interacts with the commitment in their zkApp

In Mina, zkApps can access each others' state freely. Thus, in order to use the commitment on the decentralized oracle Settlement Contract, all you need to do is to access this contract's state on the `method` you have in your zkApp, and verify that a certain data is inside this state with the witness you get in the above step.

### BONUS: Combining multiple settlement TXs together

In order to update the state multiple times in a block (this resolves the concurrency issue) and increase the number of data points the decentralized oracle can verify at a single block, you can also aggregate settlement TXs. (This functionality is really similar to a ZK rollup). You can find the implementation of such an aggregation proof [here](./src/aggregation/SettlementAggregation.ts).

**Important**: Usage of this function is highly recommended.

## Conclusion

To summarize, by using the functions available in this repository, you can implement a very scalable and performant decentralized oracle or bridge on top of Mina Protocol.

If you have any questions or concerns about this repository, please feel free to reach out through issues or from yunus.gurlek@minaprotocol.com.