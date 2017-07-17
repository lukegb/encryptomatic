encryptomatic
-------------

encryptomatic is a utility for automatically issuing and renewing TLS certificates using the ACME protocol.

It is primarily designed for the task of issuing and installing TLS certificates on devices which may not
themselves support ACME, such as on FreeNAS and on HP Integrated Lights Out (ILO) systems, but also supports
installing certificates on the local disk and on remote machines.

## Supported Endpoints

* Local filesystem (`file`)
* Remote server via SSH (`ssh`)
* FreeNAS (`freenas`)
* HP ILO2 (`hpilo2`)

## Supported Domain Control Verification Methods

* Cloudflare DNS (`cloudflare`)
