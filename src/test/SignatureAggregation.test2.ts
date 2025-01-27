import { Field, Poseidon, PrivateKey, PublicKey, Signature, verify, VerificationKey } from 'o1js';

import SignatureAggregation from '../aggregation/SignatureAggregation.js';

import MerkleTree from '../lib/MerkleTree.js';
import { SignatureList, SignatureWrapper, MAX_SIGNATURE_COUNT } from '../lib/SignatureList.js';

const SIGNER_COUNT = 66; // Must be an integer bigger than MAX_SIGNATURE_COUNT to test aggregation

describe('/aggregation/SettlementAggregation.ts Test', () => {
  const dataToSign = Field.random();
  const signerPrivateKeys = Array.from({ length: SIGNER_COUNT }, () => PrivateKey.random()).sort((a, b) => {
    if (Poseidon.hash(a.toPublicKey().toFields()).toBigInt() < Poseidon.hash(b.toPublicKey().toFields()).toBigInt()) return -1;
    if (Poseidon.hash(a.toPublicKey().toFields()).toBigInt() > Poseidon.hash(b.toPublicKey().toFields()).toBigInt()) return 1;
    return 0;
  });
  const signerPublicKeys = signerPrivateKeys.map(each => each.toPublicKey());

  const signersTree = MerkleTree.createFromFieldArray(signerPrivateKeys.map(each => Poseidon.hash(each.toPublicKey().toFields())));

  if (!signersTree)
    throw new Error('Tree cannot be created');

  const signatures = Array.from({ length: SIGNER_COUNT }, (_, i: number) => {
    const signer = signerPrivateKeys[i];
    const merkleTreeIndex = MerkleTree.indexOf(signerPublicKeys.map(each => each.toBase58()), signerPublicKeys[i].toBase58());

    return new SignatureWrapper(
      signer.toPublicKey(),
      Signature.create(signer, [ dataToSign ]),
      new MerkleTree.Witness(signersTree.getWitness(BigInt(merkleTreeIndex)))
    );
  });

  let verificationKey: VerificationKey;

  it('generates the verificationKey', async () => {
    console.log('Compile started.');
    console.time('compile time');
    verificationKey = (await SignatureAggregation.Program.compile()).verificationKey;
    console.timeEnd('compile time');
    console.log(`Verification Key is: ${verificationKey.hash}`);
  });

  let aggregationCount = Math.floor(SIGNER_COUNT / MAX_SIGNATURE_COUNT) + (SIGNER_COUNT % MAX_SIGNATURE_COUNT === 0 ? 0 : 1) - 1;
  let aggregationProof : SignatureAggregation.Proof;
  let validCount : Field;

  it('correctly generates the base case proof', async () => {
    const signatureList = new SignatureList(signatures.filter((_, i) => i < MAX_SIGNATURE_COUNT));

    console.time('proof base aggregation time')
    aggregationProof = (await SignatureAggregation.Program.base(
      dataToSign,
      signersTree.getRoot(),
      signatureList
    )).proof;
    console.timeEnd('proof base aggregation time');

    const isProofValid = await verify(aggregationProof, verificationKey);
    const signatureListOutput = signatureList.getValidCount(dataToSign, signersTree.getRoot());
    const publicOutput = aggregationProof.publicOutput;

    expect(isProofValid).toEqual(true);
    expect(publicOutput.count.equals(signatureListOutput.count).toBoolean()).toEqual(true);
    expect(publicOutput.greatestSignerHash.equals(signatureListOutput.greatest_signature_hash).toBoolean()).toEqual(true);
    expect(publicOutput.message.equals(dataToSign).toBoolean()).toEqual(true);
    expect(publicOutput.signersTreeRoot.equals(signersTree.getRoot()).toBoolean()).toEqual(true);

    validCount = publicOutput.count;
  });

  for (let i = 1; i < aggregationCount + 1; i++)
    it(`correctly generates the ${i}. proof`, async () => {
      const signatureList = new SignatureList(signatures.filter((_, j) => j > MAX_SIGNATURE_COUNT * i && j < MAX_SIGNATURE_COUNT * (i + 1)));

      console.time(`proof step ${i} base aggregation time`)
      aggregationProof = (await SignatureAggregation.Program.step(
        aggregationProof,
        signatureList
      )).proof;
      console.timeEnd(`proof step ${i} base aggregation time`)

      const isProofValid = await verify(aggregationProof, verificationKey);
      const signatureListOutput = signatureList.getValidCount(dataToSign, signersTree.getRoot());
      const publicOutput = aggregationProof.publicOutput;

      validCount = validCount.add(signatureListOutput.count);

      expect(isProofValid).toEqual(true);
      expect(publicOutput.count.equals(validCount).toBoolean()).toEqual(true);
      expect(publicOutput.greatestSignerHash.equals(signatureListOutput.greatest_signature_hash).toBoolean()).toEqual(true);
      expect(publicOutput.message.equals(dataToSign).toBoolean()).toEqual(true);
      expect(publicOutput.signersTreeRoot.equals(signersTree.getRoot()).toBoolean()).toEqual(true);
    });
});