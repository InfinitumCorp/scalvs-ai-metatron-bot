# Scalvs.ai Metatron Bot

Motion bot for Scalvs.ai featuring a clean 3D Metatron’s Cube icon.

## Icon Concept

- Minimal white-on-black sacred geometry
- Outer cube frame with corner spheres
- Central star tetrahedron (Merkaba)
- Uncluttered, modern bot avatar style (inspired by Grok bots)
- Pure monochrome for maximum clarity at small sizes

## Iterations

1. Full detailed 3D lattice with cyan glow
2. Simplified structure with reduced internal lines
3. Pure black & white version (final clean icon direction)

## Bot

Grok Bot: **Scalvs.ai Metatron Bot**
- Handles icon generation, refinements, motion concepts, and related design tasks
- Precise, uncluttered style matching modern bot avatars

Repo initialized for asset and concept tracking.

## Product tools

The bot tools are a Python package, `scalvs_metatron`. Geo routing is an
opt-in cyber policy annotation. It is off by default, and while it is off the
policy, annotation, and log output stay on the default path.

Persist the toggle:

```bash
python -m scalvs_metatron settings --geo-routing off
python -m scalvs_metatron settings --geo-routing on
python -m scalvs_metatron settings
```

`INFINITUM_GEO_ENABLED=on` or `off` overrides the saved toggle for one process.
`--geo-routing` and `--no-geo-routing` on `annotate` and `policy` do the same
without writing the settings file. A process flag wins over the environment.

Datasets are pinned in `data/geo.lock.json` and are not committed. Fetch them
after you turn geo routing on:

```bash
python scripts/fetch_geo_data.py
```

The script checks the official `.sha256sum` assets, then the downloaded bytes,
and stops without keeping a bad file if either hash differs. See
`THIRD_PARTY_NOTICES` for attribution.

```bash
python -m unittest discover -s tests -v
```