# Maritime Component Audit

This snapshot contains the evaluated 0.1.0-rc4 verifier, source code, inputs,
study scripts, figure generators and validation evidence. The offline core
requires Python 3.11 or later. Run these commands from the extracted root.

```sh
sha256sum -c SHA256SUMS.txt
python3 -m pip install .
(cd software && python3 src/check_release.py && python3 -m unittest discover -s tests && python3 examples/demo.py)
```

See [the developer manual](software/README.md) for reproduction commands and
[the input manifest](software/inputs/SOURCES.md) for sources and licences.
