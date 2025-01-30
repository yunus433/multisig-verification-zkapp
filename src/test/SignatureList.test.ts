import { Field, MerkleMap, MerkleMapWitness, Poseidon, PrivateKey, PublicKey, Signature } from 'o1js';

import { SIGNATURE_COUNT_PER_LIST } from '../lib/constants.js';
import { SignatureWrapper, SignatureList } from '../lib/SignatureList.js';

const SIGNER_COUNT = Math.floor(SIGNATURE_COUNT_PER_LIST * Math.random()); // Must be an integer between 1 and SIGNATURE_COUNT_PER_LIST

describe('/lib/SignatureList.ts Test', () => {
  const dataToSign = Field.random();
  const signerPrivateKeys = Array.from({ length: SIGNER_COUNT }, () => PrivateKey.random()).sort((a, b) => {
    if (Poseidon.hash(a.toPublicKey().toFields()).toBigInt() < Poseidon.hash(b.toPublicKey().toFields()).toBigInt()) return -1;
    if (Poseidon.hash(a.toPublicKey().toFields()).toBigInt() > Poseidon.hash(b.toPublicKey().toFields()).toBigInt()) return 1;
    return 0;
  });
  const signerPublicKeys = signerPrivateKeys.map(each => each.toPublicKey());

  const signersTree = new MerkleMap();
  signerPublicKeys.forEach(pubKey => signersTree.set(Poseidon.hash(pubKey.toFields()), Field(1)));

  it('creates SignatureWrapper', () => {
    const index = Math.floor(Math.random() * SIGNER_COUNT);
    const signer = signerPrivateKeys[index];

    const signatureWrapper = new SignatureWrapper(
      signer.toPublicKey(),
      Signature.create(signer, [ dataToSign ]),
      signersTree.getWitness(Poseidon.hash(signer.toPublicKey().toFields()))
    );

    expect(signatureWrapper.publicKey.equals(signer.toPublicKey()).toBoolean()).toEqual(true);
    expect(signatureWrapper.signature.verify(signer.toPublicKey(), [ dataToSign ]).toBoolean()).toEqual(true);
    const [witnessRoot, witnessKey] = signatureWrapper.witness.computeRootAndKey(Field(1));
    expect(witnessRoot.equals(signersTree.getRoot()).toBoolean()).toEqual(true);
    expect(witnessKey.equals(Poseidon.hash(signer.toPublicKey().toFields())).toBoolean()).toEqual(true);
  });

  const signatures = Array.from({ length: SIGNER_COUNT }, (_, i: number) => {
    const signer = signerPrivateKeys[i];

    return new SignatureWrapper(
      signer.toPublicKey(),
      Signature.create(signer, [ dataToSign ]),
      signersTree.getWitness(Poseidon.hash(signer.toPublicKey().toFields()))
    );
  });

  let signatureList: SignatureList;

  it('creates SignatureList', () => {
    signatureList = new SignatureList(signatures);

    for (let i = 0; i < SIGNATURE_COUNT_PER_LIST; i++) {
      const signatureWrapper = signatureList.list[i];

      if (i < SIGNER_COUNT) {
        expect(signatureWrapper.publicKey.equals(signatures[i].publicKey).toBoolean()).toEqual(true);
        expect(signatureWrapper.signature.equals(signatures[i].signature).toBoolean()).toEqual(true);
        expect(signatureWrapper.witness.equals(signatures[i].witness).toBoolean()).toEqual(true);
        expect(signatureWrapper.verify(dataToSign, signersTree.getRoot()).toBoolean()).toEqual(true);
      } else {
        expect(signatureWrapper.isEmpty().toBoolean()).toEqual(true);
      }
    }
  });

  it('verifies and counts SignatureList', () => {
    const output = signatureList.getValidCount(dataToSign, signersTree.getRoot());

    expect(output.count.equals(Field(SIGNER_COUNT)).toBoolean()).toEqual(true);
    expect(output.smallest_signature_hash.equals(Poseidon.hash(signerPublicKeys[0].toFields())).toBoolean()).toEqual(true);
    expect(output.greatest_signature_hash.equals(Poseidon.hash(signerPublicKeys[SIGNER_COUNT - 1].toFields())).toBoolean()).toEqual(true);
  });

  it('verifies and counts while the order is ascending', () => {
    const index = Math.floor(Math.random() * (SIGNER_COUNT - 1));

    const temp = {
      publicKey: signatures[index].publicKey.toBase58(),
      signature: signatures[index].signature.toBase58(),
      witness: signatures[index].witness.toJSON(),
    };
    signatures[index] = signatures[SIGNER_COUNT - 1];
    signatures[SIGNER_COUNT - 1] = new SignatureWrapper(
      PublicKey.fromBase58(temp.publicKey),
      Signature.fromBase58(temp.signature),
      MerkleMapWitness.fromJSON(temp.witness)
    );

    const validCount = index + 1;

    const notOrderedSignatureList = new SignatureList(signatures);
    const output = notOrderedSignatureList.getValidCount(dataToSign, signersTree.getRoot());

    expect(output.count.equals(Field(validCount)).toBoolean()).toEqual(true);
    expect(output.smallest_signature_hash.equals(Poseidon.hash(signatures[0].publicKey.toFields())).toBoolean()).toEqual(true);
    expect(output.greatest_signature_hash.equals(Poseidon.hash(signatures[index].publicKey.toFields())).toBoolean()).toEqual(true);
  });
});
