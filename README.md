# app-eos

Eos wallet application framework for Ledger Nano S

This follows the specification available in the doc/ folder

To use the generic wallet refer to `signTransaction.py`, `getPublicKey.py` or Ledger EOS Wallet application available on Github at https://github.com/tarassh/fairy-wallet

# How to Install developer version
## Configuring Ledger Environment

* Install Vagrant and Virtualbox on your machine
* Run the following

```
git clone https://github.com/fix/ledger-vagrant
cd ledger-vagrant
vagrant up
```

This will take a few minutes to install

## Compile your ledger app

* install your app under apps/ for instance:
```
cd apps/
git clone https://github.com/tarassh/eos-ledger

```
* connect to the machine with `ssh vagrant`
* build eos app

```
cd apps/eos-ledger
make clean
make
```

* connect your ledger Nano S to your computer
* install the app on your ledger: make load
* remove the app from the ledger: make delete

Install instruction with slight modifications has been taken from [here](https://github.com/fix/ledger-vagrant)
