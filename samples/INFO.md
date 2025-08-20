# Samples

This repository includes a password-protected archive of APKs for testing **dexray-insight**:

- **Archive:** `malware_samples.zip`  
- **Password:** `infected`


> ⚠️ **Safety notice:** Handle these files in an isolated environment (VM/analysis box). Do **not** install on personal devices.

## Quick start

```bash
# List contents without extracting
unzip -P infected -l malware_samples.zip

# Extract into ./samples/
mkdir -p samples
unzip -P infected malware_samples.zip -d samples/
Archive:  malware_samples.zip
  inflating: samples/catelites_2018_01_19.apk
  inflating: samples/72888975925ABD4F55B2DD0C2C17FC68670DD8DEE1BAE2BAABC1DE6299E6CC05.apk
  inflating: samples/BianLian.apk

```

7-Zip alternative
```bash
# Works for ZIP/7z, useful if your unzip lacks AES support
7z x -p'infected' -o./samples malware_samples.zip
```

## sample informations

### catelites_2018_01_19.apk

- https://malpedia.caad.fkie.fraunhofer.de/details/apk.catelites 

Test it with:
```bash
dexray-intercept -s net.classwindexampleyear.bookseapiececountry
```


The unpacket sample of catelites_2018_01_19.apk is the `aiaucfstleo.jar`

### BianLian

- https://github.com/CodingGay/BlackDex/issues/122


### Android Banker

- Hash: 509AA4A846C6CB52E9756A282DE67DA3E8EC82769BCEAFA1265428B1289459B3
- https://www.fortinet.com/blog/threat-research/defeating-an-android-packer-with-frida
- https://www.apklab.io/apk.html?hash=509aa4a846c6cb52e9756a282de67da3e8ec82769bceafa1265428b1289459b3
