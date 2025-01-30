/*
  This is an example to show the basic functionality of a Signer Node.
  It is not a complete implementation and should be used as a reference.
*/

import { Field, PrivateKey, PublicKey, Poseidon, Signature } from 'o1js';

import { stringToFieldArray } from '../lib/utils.js'; // A custom utility function to convert a string to a Field array, it must be changed based on the need.

const VERIFIER_KEY = PublicKey.fromBase58(process.env.VERIFIER_KEY || ''); // The public key of the Verifier Node.
const PRIVATE_KEY = PrivateKey.fromBase58(process.env.PRIVATE_KEY || ''); // The private key of this Signer Node.

function validateAndSign(req: {
  signature: string,
  data: {
    url: string,
    route: string,
    field: string
  }
}) {
  try {
    const verifierSignature = Signature.fromBase58(req.signature);
    
    if (!verifierSignature.verify(VERIFIER_KEY, [ Poseidon.hash(stringToFieldArray(JSON.stringify(req.data))) ]).toBoolean()) // Verifies the signature of the Verifier Node.
      throw new Error('Unauthorized request.');

    fetch(`${req.data.url}${req.data.route}`)
      .then(res => res.json())
      .then(data => {
        if (!data[req.data.field] || typeof data[req.data.field] != 'number') // Verifies the existence of the requested field. Here, it is assumed that the field is a number.
          throw new Error('The requested field does not exist');

        const dataAsProvable = Field(BigInt(req.data.field));
        const signature = Signature.create(PRIVATE_KEY, [ dataAsProvable ]);

        return signature.toBase58();
      })
      .catch(err => {
        throw new Error(`Request failed with the error: ${err}`);
      })
  } catch (err) {
    throw new Error(`Request failed with the error: ${err}`);
  };
};