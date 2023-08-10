/* global BigInt */
import './App.css';
import init, { EtfApiWrapper, ibe_extract, random_ibe_params } from "etf";
import React, { useEffect, useState } from 'react';

function App() {
  
  const [api, setApi] = useState(null);
  const [ibeParams, setIbeParams] = useState(null);

  useEffect(() => {
    init().then(_ => {
      console.log('wasm initialized successfully');
      let ibeTestParams = random_ibe_params();
      let api = new EtfApiWrapper(ibeTestParams.p, ibeTestParams.q);
      console.log('etf api initialized');
      let version = String.fromCharCode(...api.version());
      console.log('version ' + version);
      setApi(api);
      setIbeParams(ibeTestParams);
  });
  }, [])


  function test() {
    let t = new TextEncoder();
    // await api.encrypt(...) in the future
    let ids = [
      t.encode("test_id_0"), 
      t.encode("test_id_1"),
      t.encode("test_id_2"),
    ];

    let message = t.encode("hello world");
    let threshold = 2;

    try {
      let ct = api.encrypt(message, ids, threshold);
      console.log(JSON.stringify(ct));
      console.log("Running IBE extract to get ibe secrets");
      let sks = ibe_extract(ibeParams.s, ids);
      console.log(sks);
      let plaintext = api.decrypt(ct.aes_ct.ciphertext, ct.aes_ct.nonce, ct.etf_ct, sks.map(sk => sk[0]));
      console.log(String.fromCharCode(...plaintext));
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
