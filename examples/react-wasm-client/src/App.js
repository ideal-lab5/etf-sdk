/* global BigInt */
import './App.css';
import init, {encrypt, generate_secret_key} from "etf";
import React, { useEffect, useState } from 'react';

function App() {
  
  const [api, setApi] = useState(null);
  const [ibeParams, setIbeParams] = useState(null);

  useEffect(() => {
    init().then(_ => {
      // console.log('wasm initialized successfully');
      // let ibeTestParams = random_ibe_params();
      // let api = new EtfApiWrapper(ibeTestParams.p, ibeTestParams.q);
      // console.log('etf api initialized');
      // let version = String.fromCharCode(...api.version());
      // console.log('version ' + version);
      // setApi(api);
      // setIbeParams(ibeTestParams);
  });
  }, [])


  function test() {
    let t = new TextEncoder();
    // await api.encrypt(...) in the future
    let id = t.encode("here's an id")

    let message = t.encode("hello world");
    // let sk = t.encode("sk");
    let pk = t.encode("pk");
    let threshold = 2;
    let seed = t.encode("seed");
   

    try {
      let sk = generate_secret_key(seed);
      console.log("secret key: ");
      console.log(sk);
    //   let ct = api.encrypt(message, ids, threshold, seed);
    //   console.log(JSON.stringify(ct));
    //   console.log("Running IBE extract to get ibe secrets");
    //   let sks = ibe_extract(ibeParams.s, ids);
    //   console.log(sks);
    //   let plaintext = api.decrypt(
    //     ct.aes_ct.ciphertext, ct.aes_ct.nonce, ct.etf_ct, sks.map(sk => sk[0]));
    //   console.log(String.fromCharCode(...plaintext));
      //let answer = encrypt();
      let encrypt_thing = encrypt(ids, message,sk, pk);
      console.log(encrypt_thing)
    } catch(e) {
      console.log(e);
    }
    
  }

  return (
    <div className="App">
      <div>
        <h2>ETF WASM EXAMPLE</h2>
        <div>
          <p>Encryption test: `Hello World`</p>
          <button onClick={() => test()}>Encrypt message</button>
      </div>
      </div>
    </div>
  );
}

export default App;
