import { Bool, Field, method, MerkleMapWitness, Permissions, Poseidon, PrivateKey, Provable, PublicKey, Signature, SmartContract, state, State, Struct } from 'o1js';

import SignatureAggregation from '../aggregation/SignatureAggregation.js';
import SettleAggregation from '../aggregation/SettlementAggregation.js';

import MerkleTree from '../lib/MerkleTree.js';

namespace SettleNamespace {
  export const SETTLE_CONDITION_PERCENTAGE : Field = Field(6666); // 66.66%
  export const PERCENTAGE_DIVISOR = 10000;

  export class Contract extends SmartContract {
    @state(PublicKey) verifier: State<PublicKey>;
    @state(Field) signersTreeRoot: State<Field>;
    @state(Field) signersCount: State<Field>;
    @state(Field) verifiedMessages: State<Field>;

    async deploy() {
      await super.deploy();
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
      genesisMerkleRoot: Field
    ) {
      this.account.provedState.requireEquals(Bool(false));

      this.verifier.set(verifier.toPublicKey());
      this.signersTreeRoot.set(genesisMerkleRoot);
      this.verifiedMessages.set(MerkleTree.emptyRoot());
    };

    @method
    async settle(
      verifier: PrivateKey,
      proof: SignatureAggregation.Proof,
      updateWitness: MerkleMapWitness
    ) {
      // Allow settlement only by the Verifier
      this.verifier.requireEquals(verifier.toPublicKey());

      proof.verify();

      // Verify the inclusionRoot is the same
      this.signersTreeRoot.requireEquals(proof.publicOutput.signersTreeRoot);

      // Verify the settle condition
      const signersCount = this.signersCount.getAndRequireEquals();

      // SETTLE_CONDITION_PERCENTAGE / PERCENTAGE_DIVISOR <= proof.publicOutput.count / signersCount
      SETTLE_CONDITION_PERCENTAGE.mul(signersCount).assertLessThanOrEqual(proof.publicOutput.count.mul(PERCENTAGE_DIVISOR));

      // Assert the previousRoot is correct
      const [updateRoot, updateKey] = updateWitness.computeRootAndKey(Field.from(0));
      this.verifiedMessages.requireEquals(updateRoot);
      updateKey.assertEquals(proof.publicOutput.message);

      // Compute the new root
      const [newRoot, newKey] = updateWitness.computeRootAndKey(Field.from(1));
      newKey.assertEquals(proof.publicOutput.message);

      // Update the root
      this.verifiedMessages.set(newRoot);
    };

    @method
    async aggregatedSettle( // Performs the same task as the `settle()` off-chain through ZKP aggregation, and then settles multiple updates at the same time.
      verifier: PrivateKey,
      proof: SettleAggregation.Proof
    ) {
      // Allow settlement only by the Verifier
      this.verifier.requireEquals(verifier.toPublicKey());

      proof.verify();

      // Assert the previousRoot is correct
      this.verifiedMessages.requireEquals(proof.publicOutput.newVerifiedMessagesRoot);

      // Verify the inclusionRoot is the same
      this.signersTreeRoot.requireEquals(proof.publicOutput.signersTreeRoot);

      // Verify the signerCount is the same
      this.signersCount.requireEquals(proof.publicOutput.signersCount);

      // Verify the settleConditionPercentage is the same
      SETTLE_CONDITION_PERCENTAGE.assertEquals(proof.publicOutput.settleConditionPercentage);

      // Update the root
      this.verifiedMessages.set(proof.publicOutput.newVerifiedMessagesRoot);
    };

  };
};

export default SettleNamespace;
