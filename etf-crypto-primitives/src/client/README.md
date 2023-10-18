# ETF CLIENT

Under development.

A client to encrypt messages using AES-GCM and IBE. Essentially, it :
1. uses an ephemeral secret to encrypt a message using AES-GCM
2. Uses shamir's secret sharing to shard the secret
3. Use BFIBE to encrypt the secret for your specified ids

