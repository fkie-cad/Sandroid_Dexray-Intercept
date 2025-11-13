The files in this directory are from [https://github.com/httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning) (except the file `acp_logging.js`)

### Licensing
The `LICENSE` file in this directory applies only to the files included in this directory (except the file `acp_logging.js`)


### Changes
For this project, the original source code of the files contained in this directory has been edited. The following changes were made:

- `config.js`: The 'hardcoded' `PROXY_HOST`, `PROXY_PORT`, `CERT_PEM` and `DEBUG_MODE` variables have been removed, and will be set automatically by `dexray_intercept/services/cert_pinning.py`
- All separate scripts are 'combined' to one script, by including each file in the `config.js` and compile that via `frida-compile`
- The messages printed to the console have been edited to fit the style of the rest of this project a bit better
- There occurred an error when trying to inject the certificate. This bug has been fixed (for more info on that, have a look at the file `android-system-certificate-injection.js`, lines 86-92)
- All `console.[log|error|debug]` calls, will now only be executed, if `DEBUG_MODE` is `true`