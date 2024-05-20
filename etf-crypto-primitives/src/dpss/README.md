# Dynamic-Committee Proactive Secret Sharing

This is an implementation of the following work:

https://eprint.iacr.org/2022/971.pdf

https://eprint.iacr.org/2022/971.pdf
https://www.di.ens.fr/~stern/data/St93.pdf
https://www.di.ens.fr/david.pointcheval/Documents/Papers/2000_pkcA.pdf


## Usage

TODO

``` shell
cargo +nightly build
```

## API

We present two APIs. The HighThresholdACSS API is used internally by the DPSS one. ACSS stands for asynchronous complete secret sharing. The high threshold variant ensures that the privacy threshold $d$ does not need to be the same as the threshold $t$. $d$ can be between $t$ and $|C| - t- 1$ where C is the committee.

### HighThresholdACSS

- keygen
- share_producer
- share_receiver
- reconstruct

### Dynamic Committee Secret Sharing

- reshare_producer
- reshare_recever

## Testing

## Security
