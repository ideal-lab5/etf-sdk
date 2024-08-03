/* global BigInt */
import './App.css';
import init, { encrypt, decrypt } from "etf";
import React, { useEffect, useState} from 'react';
import { sha256 } from '@noble/hashes/sha256'
import { hexToU8a } from '@polkadot/util';
import {Buffer} from 'buffer'

function App() {

  useEffect(() => {
    console.log("component rendered or updated");
    init().then(_ => {
    });
  }, [])

  const [inputs, setInputs] = useState({
    message: '',
    cipherText:'',
    decrypted_text: '',
    isEncrypted: false,
    isDecrypted: false
  })

  const handleChange = (event) => {
    const { name, value } = event.target;
    setInputs((prevInputs) => ({
        ...prevInputs,
        [name]: value
    }));
  };

  // valid values from Drand's Quicknet
  // 96 bytes
  const PUB_KEY = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
  const VALID_TIXEL = 
  {
    "round": 9966538,
    "randomness": "8c05368ddff9cc8f518160966e50744ee951b2a78ca51d212f47a718bf280d6a",
    "signature": "801851c0abb76bb177132925d5fa7f0acdf58a0fc95f2f75565ced3f09d3cfb3efb14b211a2dff4194566eec4f00ade9"
  };

  function tle() {
    let t = new TextEncoder();
    let id = sha256(roundBuffer(VALID_TIXEL.round));
    let message = t.encode(inputs.message);
    // aes secret kye
    let sk = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
    // drand public key
    let pp = hexToU8a(PUB_KEY);

    try {
      // compute: ciphertext = tle(drand_id, message_to_encrypt, aes_secret_key, drand_public_key)
      let ciphertext = encrypt(id, message, sk, pp);
      console.log(ciphertext)
      setInputs((prevInputs) => ({
        ...prevInputs,
        cipherText: ciphertext,
        isEncrypted: true
      }));
      console.log("encryption complete");
    } catch(e) {
      console.log(e);
    }
    
  }

// from https://github.com/drand/drand-client/blob/master/lib/beacon-verification.ts#L104
function roundBuffer(round) {
    const buffer = Buffer.alloc(8)
    buffer.writeBigUInt64BE(BigInt(round))
    return buffer
}
  
  function decrypt_endpoint() {
    let sig = hexToU8a(VALID_TIXEL.signature);
    let decrypt_message = decrypt(inputs.cipherText, sig);
    setInputs((prevInputs) => ({
      ...prevInputs,
      decrypted_text: decrypt_message,
      isDecrypted: true
    }));
  }

  return (
    <div className="App">
      <div>
        <h2>ETF WASM EXAMPLE</h2>
        <div>
          <p>Encryption test</p>
          <label>Message to Encrypt</label>
          <div><input name = "message" value={inputs.message} type="text" onChange={handleChange}/></div>
          <button onClick={() => tle()}>Encrypt message</button>
          <div>
            {inputs.isEncrypted? (
              <div>
                <div>
                  <label>CipherText</label>
                  <p className='ct-display'>{ '0x' + Array.from(inputs.cipherText, function(byte) {
                            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
                          }).join('') }
                  </p>
                </div>
                <div>
                    <button onClick={() => decrypt_endpoint()}>Decrypt</button>
                </div>
              </div>
            ) : null}
          </div>

          <div>
            {inputs.isDecrypted? (
              <div>
                <label>Decrypted Text:</label>
                <div>{inputs.decrypted_text}</div>
              </div>
            ) : null}
          </div>

      </div>
      </div>
    </div>
  );
}

export default App;
