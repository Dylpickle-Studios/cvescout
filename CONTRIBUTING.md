# Contributing

1. Open issue describing bug or narrow feature.
2. Keep Pi Zero resource limits in mind.
3. Avoid new dependencies unless standard library or existing stack cannot solve problem clearly.
4. Add focused tests for parsing, validation, or security-sensitive branches.
5. Run `python -m unittest discover -v`.

For new active checker, document why probe is non-destructive, bound its time and response size, hard-code script/arguments, and add test proving user input cannot select arbitrary scripts.

By contributing, you agree contribution is licensed under MIT license.
