# WASM DKG with React

wasm wrappers for the dkg core library, allows for use within the browser

## Build

First build the api lib and compile the was wasm. From the [api](../api/) directory, run the `wasm_build.sh` script:

``` bash
cargo build
# build for web target
wasm-pack build --target web
```

## Troubleshooting

If you encounter an error like: `export 'default' (imported as 'init') was not found in 'dkg'`, this most likely indicates that the wasm library was builder with `--target bunder`. To fix this, rebuild the wasm using `--target web` only.