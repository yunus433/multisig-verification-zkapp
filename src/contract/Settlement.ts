import { Bool, Field, method, MerkleMapWitness, Permissions, Poseidon, PrivateKey, Provable, PublicKey, Signature, SmartContract, state, State, Struct, MerkleMap } from 'o1js';

import SignatureAggregation from '../aggregation/SignatureAggregation.js';
import SettleAggregation from '../aggregation/SettlementAggregation.js';

import { SETTLE_CONDITION_PERCENTAGE, PERCENTAGE_DIVISOR } from '../lib/constants.js';
import { stringToFieldArray } from '../lib/utils.js';

namespace SettlementNamespace {
  const SIGNER_NODE_ADD_MESSAGE_PREFIX = Poseidon.hash(stringToFieldArray('signer-node-addition'));
  const SIGNER_NODE_REM_MESSAGE_PREFIX = Poseidon.hash(stringToFieldArray('signer-node-removal'));

  export class Contract extends SmartContract {
    @state(PublicKey) verifier = State<PublicKey>();
    @state(Field) signersTreeRoot= State<Field>();
    @state(Field) signersCount = State<Field>();
    @state(Field) verifiedDataTreeRoot= State<Field>();

    async deploy() {
      await super.deploy();

      this.verifier.set(PublicKey.empty());
      this.signersTreeRoot.set(Field(0));
      this.signersCount.set(Field(0));
      this.verifiedDataTreeRoot.set(Field(0));

      this.account.permissions.set({
        ...Permissions.default(),
        send: Permissions.proof(),
        setPermissions: Permissions.impossible(),
        setVerificationKey:
          Permissions.VerificationKey.impossibleDuringCurrentVersion(),
      });
    };

    @method
    async initialize(
      verifier: PrivateKey,
      genesisSignersTreeRoot: Field,
      signersCount: Field
    ) {
      this.account.provedState.requireEquals(Bool(false));

      this.verifier.set(verifier.toPublicKey());
      this.signersTreeRoot.set(genesisSignersTreeRoot);
      this.signersCount.set(signersCount);
      this.verifiedDataTreeRoot.set((new MerkleMap()).getRoot());
    };

    @method
    async settle(
      verifier: PrivateKey,
      proof: SignatureAggregation.Proof,
      updateWitness: MerkleMapWitness
    ) {
      this.verifier.requireEquals(verifier.toPublicKey());

      proof.verify();

      this.signersTreeRoot.requireEquals(proof.publicOutput.signersTreeRoot);

      const signersCount = this.signersCount.getAndRequireEquals();

      // SETTLE_CONDITION_PERCENTAGE / PERCENTAGE_DIVISOR <= proof.publicOutput.count / signersCount
      SETTLE_CONDITION_PERCENTAGE.mul(signersCount).assertLessThanOrEqual(proof.publicOutput.count.mul(PERCENTAGE_DIVISOR));

      const [updateRoot, updateKey] = updateWitness.computeRootAndKey(Field(0));
      this.verifiedDataTreeRoot.requireEquals(updateRoot);
      updateKey.assertEquals(proof.publicOutput.message);

      const [newRoot, _] = updateWitness.computeRootAndKey(Field(1));
      this.verifiedDataTreeRoot.set(newRoot);
    };

    @method
    async aggregatedSettle( // Performs the same task as the `settle()` off-chain through ZKP aggregation, and then settles multiple updates at the same time.
      verifier: PrivateKey,
      proof: SettleAggregation.Proof
    ) {
      this.verifier.requireEquals(verifier.toPublicKey());

      proof.verify();

      this.verifiedDataTreeRoot.requireEquals(proof.publicOutput.newVerifiedMessagesRoot);

      this.signersTreeRoot.requireEquals(proof.publicOutput.signersTreeRoot);

      this.signersCount.requireEquals(proof.publicOutput.signersCount);

      SETTLE_CONDITION_PERCENTAGE.assertEquals(proof.publicOutput.settleConditionPercentage);

      this.verifiedDataTreeRoot.set(proof.publicOutput.newVerifiedMessagesRoot);
    };

    @method
    async addSigner(
      verifier: PrivateKey,
      proof: SignatureAggregation.Proof,
      newSigner: PublicKey,
      witness: MerkleMapWitness
    ) {
      this.verifier.requireEquals(verifier.toPublicKey());

      proof.verify();

      this.signersTreeRoot.requireEquals(proof.publicOutput.signersTreeRoot);

      const signersCount = this.signersCount.getAndRequireEquals();

      // SETTLE_CONDITION_PERCENTAGE / PERCENTAGE_DIVISOR <= proof.publicOutput.count / signersCount
      SETTLE_CONDITION_PERCENTAGE.mul(signersCount).assertLessThanOrEqual(proof.publicOutput.count.mul(PERCENTAGE_DIVISOR));

      const message = Poseidon.hash(newSigner.toFields().concat(SIGNER_NODE_ADD_MESSAGE_PREFIX));
      message.assertEquals(proof.publicOutput.message);

      const [witnessRoot, witnessKey] = witness.computeRootAndKey(Field(0));
      witnessKey.assertEquals(Poseidon.hash(newSigner.toFields()));
      this.signersTreeRoot.requireEquals(witnessRoot);

      const [newRoot, _] = witness.computeRootAndKey(Field(1));
      this.signersTreeRoot.set(newRoot);
    };

    @method
    async removeSigner(
      verifier: PrivateKey,
      proof: SignatureAggregation.Proof,
      newSigner: PublicKey,
      witness: MerkleMapWitness
    ) {
      this.verifier.requireEquals(verifier.toPublicKey());

      proof.verify();

      this.signersTreeRoot.requireEquals(proof.publicOutput.signersTreeRoot);

      const signersCount = this.signersCount.getAndRequireEquals();

      // SETTLE_CONDITION_PERCENTAGE / PERCENTAGE_DIVISOR <= proof.publicOutput.count / signersCount
      SETTLE_CONDITION_PERCENTAGE.mul(signersCount).assertLessThanOrEqual(proof.publicOutput.count.mul(PERCENTAGE_DIVISOR));

      const message = Poseidon.hash(newSigner.toFields().concat(SIGNER_NODE_REM_MESSAGE_PREFIX));
      message.assertEquals(proof.publicOutput.message);

      const [witnessRoot, witnessKey] = witness.computeRootAndKey(Field(1));
      witnessKey.assertEquals(Poseidon.hash(newSigner.toFields()));
      this.signersTreeRoot.requireEquals(witnessRoot);

      const [newRoot, _] = witness.computeRootAndKey(Field(0));
      this.signersTreeRoot.set(newRoot);
    };
  };
};

export default SettlementNamespace;
