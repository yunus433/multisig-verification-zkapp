/*
  This is an example to show the basic functionality of a Verifier Node.
  It is not a complete implementation and should be used as a reference.
*/

import { Field, JsonProof, MerkleMap, MerkleMapWitness, PrivateKey, PublicKey, Poseidon, Signature, Mina } from 'o1js';

import SignatureAggregation from '../aggregation/SignatureAggregation.js';

import Settlement from '../contract/Settlement.js';

import { SIGNATURE_COUNT_PER_LIST } from '../lib/constants.js';
import { SignatureList, SignatureWrapper }  from '../lib/SignatureList.js';
import { stringToFieldArray } from '../lib/utils.js'; // A custom utility function to convert a string to a Field array, it must be changed based on the need.

const MINA_CONTRACT_ADDRESS = PublicKey.fromBase58(process.env.MINA_CONTRACT_ADDRESS || ''); // The address of the Mina contract.
const MINA_MAINNET_RPC = process.env.MINA_MAINNET_RPC || ''; // The URL of the Mina Mainnet RPC.
const PRIVATE_KEY = PrivateKey.fromBase58(process.env.PRIVATE_KEY || ''); // The private key of this Signer Node.
const SIGNER_NODE_LIST: {
  key: PublicKey,
  url: string
}[] = [];
const SIGNER_COUNT = SIGNER_NODE_LIST.length;

Mina.setActiveInstance(Mina.Network(MINA_MAINNET_RPC)); // We set the active instance of the Mina network.

const signerNodesMerkleMap = new MerkleMap(); // MerkleMap of Signer Nodes
const verifiedDataMerkleMap = new MerkleMap(); // MerkleMap of the verified data, must be updated with each successful verification request.

let isSignatureAggregationProofCompiled = false;
let zkApp: Settlement.Contract; // We assume that the zkApp is already deployed and initialized. You can check the deployment and initialization in the test file.

// This function must be called to initialize the Verifier Node.
function initialize() {
  SIGNER_NODE_LIST.forEach(signer => {
    signerNodesMerkleMap.set(Poseidon.hash(signer.key.toFields()), Field(1));
  });
};

async function getDataToVerify(req: {
  url: string,
  route: string,
  field: string
}): Promise<Field> {
  return fetch(`${req.url}${req.route}`)
    .then(res => res.json())
    .then(data => {
      if (!data[req.field] || typeof data[req.field] != 'number') // Verifies the existence of the requested field. Here, it is assumed that the field is a number.
        throw new Error('The requested field does not exist');

      const dataAsProvable = Field(BigInt(req.field));

      return dataAsProvable;
    })
    .catch(err => {
      throw new Error(`Request failed with the error: ${err}`);
    })
};

// This function calls each signer node with the given request and returns the signature of each signer node.
function getSignaturesOfAllSigners(req: {
  signature: string,
  data: {
    url: string,
      route: string,
      field: string
  }
}): {
  key: PublicKey,
  signature: Signature
}[] {
  // Sends a request to the URL of each signer in the SIGNER_NODE_LIST array.
  // Verifies each response.
  // Makes sure that it has at least signatures of the honest majority (e.g. 66%).

  return [];
};

// This function turns the list of signatures to a SignatureList object.
function signaturesToSignatureList(signatures: {
  key: PublicKey,
  signature: Signature
}[]): SignatureList {
  return new SignatureList(signatures.map(signature => new SignatureWrapper(
    signature.key,
    signature.signature,
    signerNodesMerkleMap.getWitness(Poseidon.hash(signature.key.toFields()))
  )));
};

// Converts the signatures to a multi-signature zero-knowledge proof.
async function createMultiSigZKP(dataToVerify: Field, signatures: SignatureList): Promise<JsonProof> {
  if (!isSignatureAggregationProofCompiled)
    await SignatureAggregation.Program.compile();

  isSignatureAggregationProofCompiled = true;

  let aggregationCount = Math.floor(SIGNER_COUNT / SIGNATURE_COUNT_PER_LIST) + (SIGNER_COUNT % SIGNATURE_COUNT_PER_LIST === 0 ? 0 : 1) - 1;
  let signatureAggregationProof : SignatureAggregation.Proof;

  signatureAggregationProof = (await SignatureAggregation.Program.base(
    dataToVerify,
    signerNodesMerkleMap.getRoot(),
    new SignatureList(signatures.list.filter((_, i) => i < SIGNATURE_COUNT_PER_LIST))
  )).proof;

  for (let i = 1; i < aggregationCount + 1; i++)
    signatureAggregationProof = (await SignatureAggregation.Program.step(
      signatureAggregationProof,
      new SignatureList(signatures.list.filter((_, j) => j > SIGNATURE_COUNT_PER_LIST * i && j < SIGNATURE_COUNT_PER_LIST * (i + 1))))
    ).proof;

  return signatureAggregationProof.toJSON();
};

// Settle to Mina
async function settle(dataToVerify: Field, jsonProof: JsonProof) {
  if (!zkApp)
    zkApp = new Settlement.Contract(MINA_CONTRACT_ADDRESS);

  const proof = await SignatureAggregation.Proof.fromJSON(jsonProof);

  const txn = await Mina.transaction(PRIVATE_KEY.toPublicKey(), async () => {
    await zkApp.settle(
      PRIVATE_KEY,
      proof,
      verifiedDataMerkleMap.getWitness(dataToVerify)
    );
  });
  await txn.prove();
  await txn.sign([PRIVATE_KEY]).send(); 
};

async function verifyData(req: {
  authentication: string,
  data: {
    url: string,
    route: string,
    field: string
  }
}): Promise<MerkleMapWitness> {
  initialize();

  try {
    // Verifies the authentication (this may be a payment etc.)

    // Calls each Signer Node to get the signature of the requested field.
    const verifierSignature = Signature.create(PRIVATE_KEY, [ Poseidon.hash(stringToFieldArray(JSON.stringify(req.data))) ]);
    const signatures = getSignaturesOfAllSigners({
      signature: verifierSignature.toBase58(),
      data: req.data
    });

    const signatureList = signaturesToSignatureList(signatures); // Converts it to a SignatureList

    const dataToVerify = await getDataToVerify(req.data); // Gets the data to verify

    const multiSigZKP = await createMultiSigZKP(dataToVerify, signatureList); // Creates the multi-signature zero-knowledge proof

    await settle(dataToVerify, multiSigZKP); // Settles the proof to the Mina blockchain

    verifiedDataMerkleMap.set(dataToVerify, Field(1)); // Updates the verified data MerkleMap

    return verifiedDataMerkleMap.getWitness(dataToVerify); // Once settled to Mina, users can access the verified information through this witness
  } catch (err) {
    throw new Error(`Request failed with the error: ${err}`);
  };
};

// With each new verified data, the witness of other verified data may change.
// This function returns the witness of the verified data.
// The payment model is not through accessing a witness, it is through the verification process itself.
// Thus, if multiple people use the same data, it is enough for only one of them to ask for verification.
function getWitness(verifiedData: Field): MerkleMapWitness {
  return verifiedDataMerkleMap.getWitness(verifiedData);
}