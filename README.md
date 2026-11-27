# VANTA filter data publisher

This repository publishes signed VANTA Shields baseline data. It contains the publishing tooling and licensing information for the data. Browser sources and signing keys are stored elsewhere.

The publisher fetches EasyList, EasyPrivacy and EasyList Germany from fixed HTTPS URLs. The VANTA validators remove unsupported rules and deduplicate compatible baseline rules. The data is derived from the EasyList authors and is provided under CC BY-SA 3.0 Unported where applicable, with source hashes, revisions when available, attribution and exclusions in the accompanying manifest. See the [upstream licensing notice](https://easylist.to/pages/licence.html) and [license terms](https://creativecommons.org/licenses/by-sa/3.0/).

Each publication branch contains `filters.vfu`, `manifest.json` and `LICENSE-EasyList.txt`. The VFU envelope signs the format marker, sequence, timestamps, rule digest and exact rule bytes using Ed25519. The JSON manifest is auxiliary provenance. Browser clients authenticate the envelope directly with the compiled public key. Scriptlets, executable resources and redirect resources are excluded.

- Production data branch `filters`
- Development acceptance branch `filters-test`

On `main`, the workflow has a read-only validation mode. The publication jobs use environment secrets restricted to `main`. Scheduled production publication requires the repository variable `PUBLISH_FILTERS=true`. A publication updates one Git reference without force after every listed file has been validated and staged in a commit. Sequence numbers come from the previous authenticated package. An unchanged list is renewed when three days or less of its seven-day validity remain. The workflow runs on GitHub-hosted runners and uses no runtime package dependencies.
