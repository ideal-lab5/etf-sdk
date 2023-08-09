/* global BigInt */
import './App.css';
import init, { EtfApiWrapper } from "etf";
import React, { useEffect, useState } from 'react';

function App() {
  
  const [api, setApi] = useState(null);

  useEffect(() => {
    let p = new Uint8Array([1, 2]);
    let q = new Uint8Array([1, 3]);
    init().then(_ => {
      console.log('wasm initialized successfully');
      let api = new EtfApiWrapper(p, q);
      console.log('etf api initialized');
      let version = String.fromCharCode(...api.version());
      console.log('version ' + version);
      // api.test(new Uint8Array([new Uint8Array([1, 2, 3])]));
      setApi(api);
  });
  }, [])


  function encrypt() {
    // let t = new TextEncoder();
    // // await api.encrypt(...)
    // let ids = [t.encode("test_id_0"), t.encode("test_id_1")];

    // let ct = api.encrypt(t.encode("hello world"), ids, 1);
    // console.log(ct);
  }

  // const ApiTest = React.lazy(() => import('./Api'));

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
