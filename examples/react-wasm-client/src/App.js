/* global BigInt */
import './App.css';
import init, { EtfApiWrapper, random_ibe_params } from "etf";
import React, { useEffect, useState } from 'react';

function App() {
  
  const [api, setApi] = useState(null);

  useEffect(() => {
    let p = new Uint8Array([1, 2]);
    let q = new Uint8Array([1, 3]);
    init().then(_ => {
      console.log('wasm initialized successfully');
      let ibeTestParams = random_ibe_params();
      let api = new EtfApiWrapper(ibeTestParams.p, ibeTestParams.q);
      console.log('etf api initialized');
      let version = String.fromCharCode(...api.version());
      console.log('version ' + version);
      setApi(api);
  });
  }, [])


  function encrypt() {
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
      console.log(JSON.stringify(ct).length);
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
          <button onClick={() => encrypt()}>Encrypt message</button>
      </div>
      </div>
    </div>
  );
}

export default App;
