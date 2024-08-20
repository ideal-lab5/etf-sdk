/* global BigInt */
import './App.css';
import init, {tle, tld, generate_keys, extract_signature, build_encoded_commitment} from "etf";
import React, { useEffect, useState} from 'react';

function App() {

  const [sk, setSk] = useState(null);
  const [pp, setPp] = useState(null);

  useEffect(() => {
    console.log("component rendered or updated");
    init().then(_ => {
      let kc = generate_keys(new TextEncoder().encode("testing"));
      let sk = kc.sk;
      let pp = kc.double_public;

      setSk(sk);
      setPp(pp);
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

  async function encrypt() {

    let t = new TextEncoder();
    let id = t.encode(build_encoded_commitment(parseInt(inputs.id), 1));
    let message = t.encode(inputs.message);
    // let seed = t.encode(inputs.seed);
    console.log("encoded values, now encrypting");
   

    try {
      console.log("Encrypting for 1 block from now...");
      let new_cipherText = await tle(id, message, sk, pp);
      // update state so decrypt button is shown
      setInputs((prevInputs) => ({
        ...prevInputs,
        cipherText: new_cipherText,
        isEncrypted: true
      }));
      console.log("encryption complete");
    } catch(e) {
      console.log(e);
    }
    
  }

  function decrypt() { 
    let t = new TextEncoder();
    let id_js = t.encode(build_encoded_commitment(parseInt(inputs.id), 1));
    let sig_vec = extract_signature(id_js, sk).slice(8);
    console.log(sig_vec);
    console.log("Decrypting");
    let decrypt_message = tld(inputs.cipherText, sig_vec);
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
          <div><input name = "id" type="number" value={inputs.id} onChange={handleChange}/></div>
          <label>Seed:</label>
          <div><input name = "seed" value={inputs.seed} type="text" onChange={handleChange}/></div>
          <label>Message to Encrypt</label>
          <div><input name = "message" value={inputs.message} type="text" onChange={handleChange}/></div>
          <button onClick={() => encrypt()}>Encrypt message</button>
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
                    <button onClick={() => decrypt()}>Decrypt</button>
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
