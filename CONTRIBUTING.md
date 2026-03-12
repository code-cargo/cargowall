# Contributing to CargoWall

Welcome! We're glad you're interested in contributing to CargoWall. Whether it's a bug report, feature request, or code contribution, your help is appreciated.

## Getting Started

- **Open an issue first** — Before submitting a large change, open an issue to discuss the approach. This avoids wasted effort and helps align on direction.
- **Small fixes are welcome** — Typo corrections, documentation improvements, and small bug fixes can go straight to a PR.

## Pull Request Guidelines

- Keep PRs focused — one logical change per PR.
- Write a clear title and description. Reference the related issue (e.g., `Fixes #42`).
- Rebase your branch on `main` before submitting.
- Keep commits clean and minimal. Squash work-in-progress commits.

## Testing

Run the standard test suite:

```sh
go test ./...
```

BPF tests require root privileges:

```sh
sudo go test -v -count=1 ./bpf/
```

Make sure all tests pass before submitting your PR.

## Code Quality

We use the following tools to maintain code quality (available via `make install-tools`):

- **staticcheck** — static analysis (`make vet`)
- **goimports-reviser** — import ordering and formatting (`make fmt`)
- **gofumpt** — strict Go formatting (`make fmt`)

Run `make fmt` and `make vet` before submitting. CI will reject PRs that don't pass `make fmt-check`.

## Developer Certificate of Origin (DCO)

CargoWall is licensed under [Apache 2.0](LICENSE). All contributions must include a DCO sign-off to certify that you have the right to submit the work under this license.

Add a `Signed-off-by` line to each commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

You can do this automatically with the `-s` flag:

```sh
git commit -s -m "Your commit message"
```

By signing off, you certify the following (from [developercertificate.org](https://developercertificate.org/)):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

> I certify that I have the right to submit this contribution under the open source license indicated in the file.

Please use your legal name — pseudonyms or anonymous contributions cannot be accepted for DCO purposes.
