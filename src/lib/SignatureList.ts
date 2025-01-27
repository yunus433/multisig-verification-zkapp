import { Bool, Field, MerkleMapWitness, Poseidon, PrivateKey, Provable, PublicKey, Signature, Struct } from 'o1js';

import { SIGNATURE_COUNT_PER_LIST } from './constants.js';

export const EMPTY_PRIVATE_KEY = PrivateKey.random();

const EMPTY_PUBLIC_KEY = EMPTY_PRIVATE_KEY.toPublicKey();

export class SignatureWrapper extends Struct({
  publicKey: PublicKey,
  signature: Signature,
  witness: MerkleMapWitness
}) {
  constructor(
    readonly publicKey: PublicKey,
    readonly signature: Signature,
    readonly witness: MerkleMapWitness
  ) {
    super({
      signature,
      publicKey,
      witness
    });
  };

  static empty(): SignatureWrapper {
    return new this(
      EMPTY_PUBLIC_KEY,
      Signature.empty(),
      MerkleMapWitness.empty()
    );
  };

  isEmpty(): Bool {
    return this.publicKey.equals(EMPTY_PUBLIC_KEY)
  };

  hash(): Field {
    return Poseidon.hash(this.publicKey.toFields());
  };

  verify(
    message: Field,
    root: Field
  ): Bool {
    const [witnessRoot, witnessKey] = this.witness.computeRootAndKey(Field(1));

    return this.signature.verify(this.publicKey, [ message ])
      .and(root.equals(witnessRoot))
      .and(this.hash().equals(witnessKey));
  };
};

export class SignatureListOutput extends Struct({
  count: Field,
  smallest_signature_hash: Field,
  greatest_signature_hash: Field
}) {};

export class SignatureList extends Struct({
  list: Provable.Array(SignatureWrapper, SIGNATURE_COUNT_PER_LIST)
}) {
  constructor(
    value: SignatureWrapper[]
  ) {
    if (value.length > SIGNATURE_COUNT_PER_LIST)
      throw new Error(`Please provide less than ${SIGNATURE_COUNT_PER_LIST} signatures to create a SignatureList.`)

    const completeList = value;

    while (completeList.length < SIGNATURE_COUNT_PER_LIST)
      completeList.push(SignatureWrapper.empty());

    super({ list: completeList });
    this.list = completeList;
  };

  static empty() {
    return new this(Array.from(
      { length: SIGNATURE_COUNT_PER_LIST },
      () => SignatureWrapper.empty()
    ));
  };

  getValidCount(
    message: Field,
    root: Field
  ): SignatureListOutput {
    let condition = this.list[0].verify(message, root);
    let validCount = Provable.if(condition, Field(1), Field(0));
    const smallestSignatureHash = Provable.if(condition, this.list[0].hash(), Field(0));
    let greatestSignatureHash = Provable.if(condition, this.list[0].hash(), Field(0));

    for (let i = 1; i < SIGNATURE_COUNT_PER_LIST; i++) {
      condition = condition.and(this.list[i].verify(message, root).and(
        this.list[i].hash().greaterThan(this.list[i - 1].hash())
      ));
      validCount = validCount.add(Provable.if(condition, Field(1), Field(0)));
      greatestSignatureHash = Provable.if(condition, this.list[i].hash(), greatestSignatureHash);
    };

    return {
      count: validCount,
      smallest_signature_hash: smallestSignatureHash,
      greatest_signature_hash: greatestSignatureHash
    };
  };
};
