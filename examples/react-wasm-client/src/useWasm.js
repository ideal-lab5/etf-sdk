import { useEffect, useState } from 'react';
import init, { EtfApiWrapper } from "etf";

export const useWasm = (p, q) => {

  const [state, setState] = useState(null);
  const [api, setApi] = useState(null);

  useEffect(() => { 
    init().then(etf => {
        console.log('wasm initialized successfully');
        let api = new EtfApiWrapper(p, q);
        console.log('etf api initialized');
        setState(etf);
        setApi(api);
    });
  }, []);
  return api;
}

