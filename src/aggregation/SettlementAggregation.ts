import { Field, MerkleMapWitness, SelfProof, Struct, ZkProgram } from 'o1js';

import { PERCENTAGE_DIVISOR } from '../lib/constants.js';

import SignatureAggregation from './SignatureAggregation.js';

namespace SettlementAggregationNamespace {
  export class PublicOutputs extends Struct({
    initialVerifiedMessagesRoot: Field,
    signersTreeRoot: Field,
    signersCount: Field,
    settleConditionPercentage: Field,
    newVerifiedMessagesRoot: Field,
  }) {};
  
  export const Program = ZkProgram({
    name: 'SettlementAggregationProgram',
    publicOutput: PublicOutputs,
  
    methods: {
      base: {
        privateInputs: [Field, Field, Field, Field],
  
        async method(
          initialVerifiedMessagesRoot: Field,
          signersTreeRoot: Field,
          signersCount: Field,
          settleConditionPercentage: Field
        ) {

          return { publicOutput: {
            initialVerifiedMessagesRoot,
            signersTreeRoot,
            signersCount,
            settleConditionPercentage,
            newVerifiedMessagesRoot: initialVerifiedMessagesRoot
          }};
        }
      },
      step: {
        privateInputs: [SelfProof, SignatureAggregation.Proof, MerkleMapWitness],
  
        async method(
          previousProof: SelfProof<void, PublicOutputs>,
          signatureAggregationProof: SignatureAggregation.Proof,
          updateWitness: MerkleMapWitness
        ) {
          previousProof.verify();
          signatureAggregationProof.verify();

          const state = previousProof.publicOutput;
          const update = signatureAggregationProof.publicOutput;

          state.signersTreeRoot.assertEquals(update.signersTreeRoot);
          state.settleConditionPercentage.mul(state.signersCount).assertLessThanOrEqual(update.count.mul(PERCENTAGE_DIVISOR));
          
          const [ previousRoot, previousKey ] = updateWitness.computeRootAndKey(Field.from(0));
          state.newVerifiedMessagesRoot.assertEquals(previousRoot);
          update.message.assertEquals(previousKey);

          const [ newRoot, _ ] = updateWitness.computeRootAndKey(Field.from(1));

          return { publicOutput: {
            initialVerifiedMessagesRoot: state.initialVerifiedMessagesRoot,
            signersTreeRoot: state.signersTreeRoot,
            signersCount: state.signersCount,
            settleConditionPercentage: state.settleConditionPercentage,
            newVerifiedMessagesRoot: newRoot
          }};
        }
      }
    }
  });

  export class Proof extends ZkProgram.Proof(Program) {}
};

export default SettlementAggregationNamespace;