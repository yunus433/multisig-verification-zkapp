// This file also retests SignatureAggregation as this proof is used during the settlement.

import { AccountUpdate, Field, MerkleMap, MerkleMapWitness, Mina, Poseidon, PrivateKey, PublicKey, Signature, VerificationKey, verify } from 'o1js';

import Settle from '../contract/Settlement.js';

import SignatureAggregation from '../aggregation/SignatureAggregation.js';

import { SIGNATURE_COUNT_PER_LIST } from '../lib/constants.js';
import { SignatureList, SignatureWrapper } from '../lib/SignatureList.js';

const SIGNER_COUNT = 66; // Must be an integer bigger than SIGNATURE_COUNT_PER_LIST to test aggregation

describe('/contract/Settle.ts Test', () => {
  let deployerAccount: Mina.TestPublicKey,
    deployerKey: PrivateKey,
    senderAccount: Mina.TestPublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: Settle.Contract;

  const verifier = PrivateKey.random();
  const signersCount = Field(SIGNER_COUNT);
  const verifiedDataTreeRoot = new MerkleMap();
  const signersTree = new MerkleMap();

  const dataToSign = Field.random();
  const signerPrivateKeys = Array.from({ length: SIGNER_COUNT }, () => PrivateKey.random()).sort((a, b) => {
    if (Poseidon.hash(a.toPublicKey().toFields()).toBigInt() < Poseidon.hash(b.toPublicKey().toFields()).toBigInt()) return -1;
    if (Poseidon.hash(a.toPublicKey().toFields()).toBigInt() > Poseidon.hash(b.toPublicKey().toFields()).toBigInt()) return 1;
    return 0;
  });
  const signerPublicKeys = signerPrivateKeys.map(each => each.toPublicKey());
  signerPublicKeys.forEach(pubKey => signersTree.set(Poseidon.hash(pubKey.toFields()), Field(1)));

  const signatures = Array.from({ length: SIGNER_COUNT }, (_, i: number) => {
    const signer = signerPrivateKeys[i];

    return new SignatureWrapper(
      signer.toPublicKey(),
      Signature.create(signer, [ dataToSign ]),
      signersTree.getWitness(Poseidon.hash(signer.toPublicKey().toFields()))
    );
  });

  let verificationKey: VerificationKey;

  async function compile() {
    console.log('compiling contract...');
    console.time('contract compile time');
    await Settle.Contract.compile();
    console.timeEnd('contract compile time');
  
    const Local = await Mina.LocalBlockchain({ proofsEnabled: true });
    Mina.setActiveInstance(Local);
  
    [deployerAccount, senderAccount] = Local.testAccounts;
    deployerKey = deployerAccount.key;
    senderKey = senderAccount.key;
  
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
  
    zkApp = new Settle.Contract(zkAppAddress);
  };

  it('generates the verificationKey for aggregation proof', async () => {
    console.log('aggregation proof compile started...');
    console.time('aggregation proof compile time');
    verificationKey = (await SignatureAggregation.Program.compile()).verificationKey;
    console.timeEnd('aggregation proof compile time');
    console.log(`verification key is: ${verificationKey.hash}`);
    await compile();
  });

  it('deploys and initializes contract', async () => {
    const txn = await Mina.transaction(deployerAccount, async () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      await zkApp.deploy();
      await zkApp.initialize(
        verifier,
        signersTree.getRoot(),
        signersCount
      );
    });
    await txn.prove();
    await txn.sign([deployerKey, zkAppPrivateKey]).send();

    expect(zkApp.verifier.get().equals(verifier.toPublicKey())).toEqual(true);
    expect(zkApp.signersTreeRoot.get().equals(signersTree.getRoot())).toEqual(true);
    expect(zkApp.signersCount.get().equals(signersCount)).toEqual(true);
    expect(zkApp.verifiedDataTreeRoot.get().equals(verifiedDataTreeRoot.getRoot())).toEqual(true);
  });

  let aggregationCount = Math.floor(SIGNER_COUNT / SIGNATURE_COUNT_PER_LIST) + (SIGNER_COUNT % SIGNATURE_COUNT_PER_LIST === 0 ? 0 : 1) - 1;
  let signatureAggregationProof : SignatureAggregation.Proof;
  let validCount : Field;

  it('generates the base case aggregation proof', async () => {
    const signatureList = new SignatureList(signatures.filter((_, i) => i < SIGNATURE_COUNT_PER_LIST));

    console.time('proof base aggregation time')
    signatureAggregationProof = (await SignatureAggregation.Program.base(
      dataToSign,
      signersTree.getRoot(),
      signatureList
    )).proof;
    console.timeEnd('proof base aggregation time');

    const isProofValid = await verify(signatureAggregationProof, verificationKey);
    const signatureListOutput = signatureList.getValidCount(dataToSign, signersTree.getRoot());
    const publicOutput = signatureAggregationProof.publicOutput;

    expect(isProofValid).toEqual(true);
    expect(publicOutput.count.equals(signatureListOutput.count).toBoolean()).toEqual(true);
    expect(publicOutput.greatestSignerHash.equals(signatureListOutput.greatest_signature_hash).toBoolean()).toEqual(true);
    expect(publicOutput.message.equals(dataToSign).toBoolean()).toEqual(true);
    expect(publicOutput.signersTreeRoot.equals(signersTree.getRoot()).toBoolean()).toEqual(true);

    validCount = publicOutput.count;
  });

  for (let i = 1; i < aggregationCount + 1; i++)
    it(`generates the ${i}. aggregation proof`, async () => {
      const signatureList = new SignatureList(signatures.filter((_, j) => j > SIGNATURE_COUNT_PER_LIST * i && j < SIGNATURE_COUNT_PER_LIST * (i + 1)));

      console.time(`proof step ${i} base aggregation time`)
      signatureAggregationProof = (await SignatureAggregation.Program.step(
        signatureAggregationProof,
        signatureList
      )).proof;
      console.timeEnd(`proof step ${i} base aggregation time`)

      const isProofValid = await verify(signatureAggregationProof, verificationKey);
      const signatureListOutput = signatureList.getValidCount(dataToSign, signersTree.getRoot());
      const publicOutput = signatureAggregationProof.publicOutput;

      validCount = validCount.add(signatureListOutput.count);

      expect(isProofValid).toEqual(true);
      expect(publicOutput.count.equals(validCount).toBoolean()).toEqual(true);
      expect(publicOutput.greatestSignerHash.equals(signatureListOutput.greatest_signature_hash).toBoolean()).toEqual(true);
      expect(publicOutput.message.equals(dataToSign).toBoolean()).toEqual(true);
      expect(publicOutput.signersTreeRoot.equals(signersTree.getRoot()).toBoolean()).toEqual(true);
    });

  it('settles the aggregation proof', async () => {
    const txn = await Mina.transaction(deployerAccount, async () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      await zkApp.settle(
        verifier,
        signatureAggregationProof,
        verifiedDataTreeRoot.getWitness(dataToSign)
      );
    });
    await txn.prove();
    await txn.sign([deployerKey, zkAppPrivateKey]).send();

    verifiedDataTreeRoot.set(dataToSign, Field(1));

    expect(zkApp.verifier.get().equals(verifier.toPublicKey())).toEqual(true);
    expect(zkApp.signersTreeRoot.get().equals(signersTree.getRoot())).toEqual(true);
    expect(zkApp.signersCount.get().equals(signersCount)).toEqual(true);
    expect(zkApp.verifiedDataTreeRoot.get().equals(verifiedDataTreeRoot.getRoot())).toEqual(true);
  })
});
