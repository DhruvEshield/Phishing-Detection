# ML Training Data

> How the detection corpus is sourced. The raw emails are **gitignored** (large) — this file is
> the committed record of provenance and how to reconstitute them. See also
> [.claude/context/ml.md](../../.claude/context/ml.md).

## What's here

```
ml/data/
├── README.md                      # this file (committed)
└── phishing_pot/
    ├── email/                     # 8,614 real phishing .eml  (gitignored — ~420 MB)
    ├── SOURCE_README.md           # upstream phishing_pot README (committed)
    └── LICENSE                    # upstream license (committed)
```

## phishing_pot — the phishing (positive) class

- **8,614 real phishing emails** in raw `.eml` (full MIME: headers, bodies, URLs, attachments,
  QR images). Collected via honeypots.
- **Source:** the public [phishing_pot](https://github.com/rf-peixoto/phishing_pot) project,
  vendored into this repo on 2026-06-25 as a stable snapshot we build on.
- **Why it's ideal:** real modern phishing with intact headers and URLs — usable both to train
  the content classifier AND as fixtures for the header / URL / QR detectors
  ([backend.md](../../.claude/context/backend.md)).

### ⚠️ Gap: no legitimate (ham) class

phishing_pot is **phishing-only**. A binary content classifier needs negatives too. Before
training, pair it with a legitimate corpus — e.g. **Enron** (`aueb.gr/users/ion/data/enron-spam`)
ham, or a sanitised internal legitimate-mail sample. Document whichever is chosen here.

## Re-fetching the gitignored emails

The `email/` directory is excluded from git (size). To restore it on a fresh clone, either ask
the maintainer for the snapshot, or re-clone the public upstream:

```bash
git clone https://github.com/rf-peixoto/phishing_pot
cp -r phishing_pot/email ml/data/phishing_pot/
```

## License / handling

- Respect `LICENSE` in this folder. Samples are anonymised upstream (addresses replaced with
  `phishing@pot`), but treat all content as sensitive per [principles.md](../../.claude/context/principles.md) #7.
- These are **detection** samples (real phishing). Simulation *templates* are deliberately out of
  scope — they're not labelled detection data.
