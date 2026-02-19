### Setup

Run a rooted Android device if you want to evaluate root checking, anti-hooking, anti-repackaging, and network integrity checking. For TEE usage, anti-debug, and code obfuscation, only an APK is required. Because most users will not have a JEB license, code obfuscation can be tricky. We recommend decompiling with jadx, an open-source decompiler, first and placing the decompiled APK under `constants.JADX_DECOMPILE_OUTPUT_PATH`.

For anti-repackaging, you will need to create a keystore. Set the password and alias in `constants/KS_PASSWORD` and `constants/KS_ALIAS`, respectively. The provided one cannot be used for anonymity.

Please carefully review `config.py` and `constants.py` and make any other required changes.

### Commands

```bash
python3 main.py -d [DIRECTORY PATH OF APK FILES]
```

```bash
python3 main.py -f [APK FILE PATH]
```

```bash
python3 main.py -s [DIRECTORY PATH OF SPLIT APK]
```

### Dependencies

TEE - This check uses `has_TEE.jar` under `./dependencies`.

DroidBot - This is included under `./dependencies/droidbot/`. If this version does not work, please try cloning from the original [repo](https://github.com/honeynet/droidbot).

[JEB](https://www.pnfsoftware.com/jeb/#android) - This is a commercial decompiler that you must purchase to use, so a copy is not included. Check `constants.py` for path settings.