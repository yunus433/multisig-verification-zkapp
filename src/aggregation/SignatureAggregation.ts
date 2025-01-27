import { Field, SelfProof, Struct, ZkProgram } from 'o1js';

import { SignatureList } from '../lib/SignatureList.js';

namespace SignatureAggregationNamespace {
  export class PublicOutputs extends Struct({
    count: Field,
    message: Field,
    signersTreeRoot: Field,
    greatestSignerHash: Field
  }) {};
  
  export const Program = ZkProgram({
    name: 'SignatureAggregationProgram',
    publicOutput: PublicOutputs,
  
    methods: {
      base: {
        privateInputs: [Field, Field, SignatureList],
  
        async method(
          message: Field,
          signersTreeRoot: Field,
          signatures: SignatureList
        ) {
          const output = signatures.getValidCount(message, signersTreeRoot);

          return { publicOutput: {
            count: output.count,
            message,
            signersTreeRoot,
            greatestSignerHash: output.greatest_signature_hash
          }};
        }
      },
      step: {
        privateInputs: [SelfProof, SignatureList],

        async method(
          previousProof: SelfProof<void, PublicOutputs>,
          signatures: SignatureList
        ) {
          const output = signatures.getValidCount(previousProof.publicOutput.message, previousProof.publicOutput.signersTreeRoot);

          output.smallest_signature_hash.assertGreaterThan(previousProof.publicOutput.greatestSignerHash);

          return { publicOutput: {
            count: previousProof.publicOutput.count.add(output.count),
            message: previousProof.publicOutput.message,
            signersTreeRoot: previousProof.publicOutput.signersTreeRoot,
            greatestSignerHash: output.greatest_signature_hash
          }};
        }
      }
    }
  });

  export class Proof extends ZkProgram.Proof(Program) {}
};

export default SignatureAggregationNamespace;