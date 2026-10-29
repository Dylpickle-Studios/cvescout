## Summary

Describe user-visible change and why it is needed.

## Validation

- [ ] `ruff check .`
- [ ] `python -m unittest discover -s tests -v`
- [ ] `python -m pip wheel --no-deps . -w dist`

## Safety

- [ ] Scan targets remain constrained to configured networks.
- [ ] No automatic, destructive, or arbitrary active checks were added.
- [ ] Logs, screenshots, and fixtures contain no credentials or real network inventory.
- [ ] Pi Zero CPU, memory, and dependency impact is acceptable.

## Documentation

- [ ] README, operations guide, changelog, or security policy updated where needed.
