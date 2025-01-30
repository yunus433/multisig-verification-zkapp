// Tests for both aggregation proofs are written in this file since the SettlementAggregation uses a SignatureAggregation proof.

import { Field, Poseidon, PrivateKey, PublicKey, Signature, verify, VerificationKey, MerkleMap, MerkleMapWitness } from 'o1js';

import SettlementAggregation from '../aggregation/SettlementAggregation.js';
import SignatureAggregation from '../aggregation/SignatureAggregation.js';

import { SignatureList, SignatureWrapper } from '../lib/SignatureList.js';
import { SIGNATURE_COUNT_PER_LIST } from '../lib/constants.js';

const SIGNER_COUNT = 66; // Must be an integer bigger than SIGNATURE_COUNT_PER_LIST to test aggregation

describe('/aggregation/SignatureAggregation.ts and /aggregation/SettlementAggregation.ts Test', () => {
  const dataToSign = Field.random();
  const signerPrivateKeys = Array.from({ length: SIGNER_COUNT }, () => PrivateKey.random()).sort((a, b) => {
    if (Poseidon.hash(a.toPublicKey().toFields()).toBigInt() < Poseidon.hash(b.toPublicKey().toFields()).toBigInt()) return -1;
    if (Poseidon.hash(a.toPublicKey().toFields()).toBigInt() > Poseidon.hash(b.toPublicKey().toFields()).toBigInt()) return 1;
    return 0;
  });
  const signerPublicKeys = signerPrivateKeys.map(each => each.toPublicKey());

  const signersTree = new MerkleMap();
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

  it('generates the verificationKey for aggregation proof', async () => {
    console.log('aggregation proof compile started...');
    console.time('aggregation proof compile time');
    verificationKey = (await SignatureAggregation.Program.compile()).verificationKey;
    console.timeEnd('aggregation proof compile time');
    console.log(`verification key is: ${verificationKey.hash}`);
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

  it('generates the verificationKey for settlement proof', async () => {
    console.log('settlement proof compile started...');
    console.time('settlement proof compile time');
    verificationKey = (await SettlementAggregation.Program.compile()).verificationKey;
    console.timeEnd('settlement proof compile time');
    console.log(`ferification key is: ${verificationKey.hash}`);
  });

  const SETTLE_CONDITION_PERCENTAGE = Field.from(6666);
  let verifiedMessagesMerkleMap = new MerkleMap();
  const initialRoot = verifiedMessagesMerkleMap.getRoot();
  let settlementAggregationProof : SettlementAggregation.Proof;

  it('generates the base case settlement proof', async () => {
    console.time('proof base settlement time')
    settlementAggregationProof = (await SettlementAggregation.Program.base(
      verifiedMessagesMerkleMap.getRoot(),
      signersTree.getRoot(),
      Field.from(signerPrivateKeys.length),
      SETTLE_CONDITION_PERCENTAGE
    )).proof;
    console.timeEnd('proof base settlement time');

    const isProofValid = await verify(settlementAggregationProof, verificationKey);
    const publicOutput = settlementAggregationProof.publicOutput;

    expect(isProofValid).toEqual(true);
    expect(publicOutput.initialVerifiedMessagesRoot.equals(initialRoot).toBoolean()).toEqual(true);
    expect(publicOutput.signersTreeRoot.equals(signersTree.getRoot()).toBoolean()).toEqual(true);
    expect(publicOutput.signersCount.equals(Field.from(signerPrivateKeys.length)).toBoolean()).toEqual(true);
    expect(publicOutput.settleConditionPercentage.equals(SETTLE_CONDITION_PERCENTAGE).toBoolean()).toEqual(true);
    expect(publicOutput.newVerifiedMessagesRoot.equals(verifiedMessagesMerkleMap.getRoot()).toBoolean()).toEqual(true);
  });

  it('generates the aggregation settlement proof', async () => {
    console.time('proof settlement aggregation time')
    settlementAggregationProof = (await SettlementAggregation.Program.step(
      settlementAggregationProof,
      signatureAggregationProof,
      verifiedMessagesMerkleMap.getWitness(dataToSign)
    )).proof;
    console.timeEnd('proof settlement aggregation time');

    const isProofValid = await verify(settlementAggregationProof, verificationKey);
    const publicOutput = settlementAggregationProof.publicOutput;

    verifiedMessagesMerkleMap.set(dataToSign, Field(1));

    expect(isProofValid).toEqual(true);
    expect(publicOutput.initialVerifiedMessagesRoot.equals(initialRoot).toBoolean()).toEqual(true);
    expect(publicOutput.signersTreeRoot.equals(signersTree.getRoot()).toBoolean()).toEqual(true);
    expect(publicOutput.signersCount.equals(Field.from(signerPrivateKeys.length)).toBoolean()).toEqual(true);
    expect(publicOutput.settleConditionPercentage.equals(SETTLE_CONDITION_PERCENTAGE).toBoolean()).toEqual(true);
    expect(publicOutput.newVerifiedMessagesRoot.equals(verifiedMessagesMerkleMap.getRoot()).toBoolean()).toEqual(true);
  });
});