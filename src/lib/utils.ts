import { Field } from 'o1js';

export const stringToFieldArray = (str: string) => {
  const POW = 256n // For UTF-8. Change this to support extended charset

  const result: Field[] = [];
  let lastField = 0n;
  
  for (let i = 0; i < str.length; i++) {
    const char = BigInt(str.charCodeAt(i));

    if (char >= POW)
      throw new Error('stringToFieldArray: This function only supports UTF-8.');

    lastField = lastField * POW + char;

    if (lastField * POW >= Field.ORDER) {
      result.push(Field.from(lastField));
      lastField = 0n;
    }
  }

  return result;
};