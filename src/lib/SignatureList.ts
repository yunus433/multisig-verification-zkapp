import { Bool, Field, Poseidon, PrivateKey, Provable, PublicKey, Signature, Struct } from 'o1js';

import MerkleTree from './MerkleTree.js';

export const EMPTY_PRIVATE_KEY = PrivateKey.random();
export const MAX_SIGNATURE_COUNT = 20;

const EMPTY_PUBLIC_KEY = EMPTY_PRIVATE_KEY.toPublicKey();

export class SignatureWrapper extends Struct({
  publicKey: PublicKey,
  signature: Signature,
  witness: MerkleTree.Witness
}) {
  constructor(
    readonly publicKey: PublicKey,
    readonly signature: Signature,
    readonly witness: MerkleTree.Witness
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
      MerkleTree.Witness.empty()
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
    return this.signature.verify(this.publicKey, [ message ])
      .and(
      root.equals(this.witness.calculateRoot(
        this.hash()
      ))
    );
  };
};

export class SignatureListOutput extends Struct({
  count: Field,
  smallest_signature_hash: Field,
  greatest_signature_hash: Field
}) {};

export class SignatureList extends Struct({
  list: Provable.Array(SignatureWrapper, MAX_SIGNATURE_COUNT)
}) {
  constructor(
    value: SignatureWrapper[]
  ) {
    if (value.length > MAX_SIGNATURE_COUNT)
      throw new Error(`Please provide less than ${MAX_SIGNATURE_COUNT} signatures to create a SignatureList.`)

    const completeList = value;

    while (completeList.length < MAX_SIGNATURE_COUNT)
      completeList.push(SignatureWrapper.empty());

    super({ list: completeList });
    this.list = completeList;
  };

  static empty() {
    return new this(Array.from(
      { length: MAX_SIGNATURE_COUNT },
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

    for (let i = 1; i < MAX_SIGNATURE_COUNT; i++) {
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
