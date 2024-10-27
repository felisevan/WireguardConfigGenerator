# WireguardConfigGenerator
A Wireguard Config Generator that supports IPv6 and more.

### Features 
* Support generate IPv6 list.
* Support preshard key. (But not user-defined due to security consideration)
* Support every item in `wg` and `wg-quick` config file.

## Usage
1. Install dependency
```
pip -r requirements.txt
```
2. Edit `config.json` according to your need.
3. Run `main.py`
   
## Dependencies
Have no dependency on wg-tools.
Only a Python 3rd library `pynacl` is needed to generate public key and private key.

## License
Using AGPL-3.0

## Appendix
[wg config file format](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8#CONFIGURATION%20FILE%20FORMAT)

[wg-quick config file format](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8#CONFIGURATION)
