/* global BigInt */
import './App.css';
import init, {encrypt, decrypt, generate_keys, extract_signature} from "etf";
import React, { useEffect, useState} from 'react';

function App() {

  useEffect(() => {
    console.log("component rendered or updated");
    init().then(_ => {

  });
  }, [])

  const [inputs, setInputs] = useState({
    id: '',
    seed: '',
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

  function encrypt_endpoint() {

    let t = new TextEncoder();
    let id = t.encode(inputs.id);
    let message = t.encode(inputs.message);
    let seed = t.encode(inputs.seed);
    console.log("encoded values, now encrypting");
   

    try {
      let kc = generate_keys(seed);
      let sk = kc.sk;
      let pp = kc.double_public;

      console.log("Encrypting");
      let new_cipherText = encrypt(id, message, sk, pp);
      // update state so decrypt button is shown
      setInputs((prevInputs) => ({
        ...prevInputs,
        cipherText: new_cipherText,
        isEncrypted: true
      }));
      console.log("encryption complete");
      console.log(inputs.isEncrypted);
    } catch(e) {
      console.log(e);
    }
    
  }

  function decrypt_endpoint() {
    let t = new TextEncoder();
    let seed = t.encode(inputs.seed);
    let kc = generate_keys(seed);
    let sk = kc.sk;
    let id_js = t.encode(inputs.id);
    let sig_vec = extract_signature(id_js, sk)
    console.log("Decrypting");
    let decrypt_message = decrypt(inputs.cipherText, sig_vec);
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

          <label>ID:</label>
          <div><input name = "id" type="text" value={inputs.id} onChange={handleChange}/></div>
          <label>Seed:</label>
          <div><input name = "seed" value={inputs.seed} type="text" onChange={handleChange}/></div>
          <label>Message to Encrypt</label>
          <div><input name = "message" value={inputs.message} type="text" onChange={handleChange}/></div>
          <button onClick={() => encrypt_endpoint()}>Encrypt message</button>
          <div>
            {inputs.isEncrypted? (
              <div>
                <div>
                  <label>CipherText</label>
                  <div>{inputs.cipherText}</div>
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
