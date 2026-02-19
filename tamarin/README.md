### Files and Folders

- `main.spthy`: The primary Tamarin model file. It imports `.spthy` files from `leaks` folder. 
- `leaks`: This folder contains all the `.spthy` files that contains rules to leak specific data elements. We included 3 min-cut sets as examples.
- `automator`: This folder contains the code that runs all variants as necessary.
- `main.py`: main file for automator

### Running automator
```bash
python3 main.py [lemma name]
```

Example:
```bash
python3 main.py TestCardCloningResistance
```


### Running Tamarin

Example (CLI mode):
```bash
tamarin-prover main.spthy --derivcheck-timeout=120 --prove -c=50
```

Example (interactive mode):
```bash
tamarin-prover interactive main.spthy --derivcheck-timeout=120 --prove -c=50
```
### Notes and Gotchas

- Start your Tamarin server from **this directory**, otherwise you may hit dependency/import errors
- Because leaks are imported into `main.spthy`, you may see this wellformedness warning/error when some elements are not leaked:

  > Facts occur in the left-hand-side but not in any right-hand-side

  Feel free to ignore it.
