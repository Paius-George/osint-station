# GitHub Username Hunter

*[Versiunea în limba română →](README.ro.md)*

An interactive CLI that finds available GitHub usernames. It scans candidate
names — either every combination of a given length, or your own word list —
and can verify each hit against GitHub's real *Change username* form, then
pre-fill it so you only have to click the final button yourself.

```
  ╔═══════════════════════════════════════╗
  ║       GitHub  Username  Hunter        ║
  ╚═══════════════════════════════════════╝
```

## Why the form check matters

The API and the public profile pages only tell you whether a name is
*registered*. GitHub also reserves a large set of unregistered names (blocked,
squatted, or system-reserved), so an "available" API result is a weak signal.

The optional form verification opens a logged-in browser, types the candidate
into the real dialog and only reports success when **three** independent
signals agree:

1. The `"<name> is available"` message on the first typed pass
2. The **Change my username** submit button being enabled.
3. The same message again after clearing and re-typing.

Anything less returns *unknown* and is skipped. Names that pass all three go to
`confirmed.txt` — those are actually claimable.

## Install

```bash
git clone https://github.com/Paius-George/Github-Username-Hunter.git
cd Github-Username-Hunter
pip install -r requirements.txt
playwright install chromium
```

Requires Python 3.10+. Chromium is only needed for form verification — skip
that step if you just want availability scanning.

A GitHub token raises your rate limit substantially:

```bash
export GITHUB_TOKEN=github_pat_xxx
```

A read-only token is enough — the script never writes anything to your account.

## Usage

```bash
python3 gh_hunter.py
```

Everything is asked interactively:

| Prompt | Options |
| --- | --- |
| **Source** | generate all combinations (1–6 chars), or load a `.txt` file |
| **Character set** | letters only, or letters + digits + hyphen |
| **Method** | GraphQL, REST, or plain web requests |
| **Verification** | check hits in the real form and pre-fill them |
| **Rate limit** | your own names/hour cap (0 = full speed) |
| **Range** | start/stop prefix, or start/stop line number for files |

When loading a list, give the path relative to the project root, e.g.
`usernames/commonwords.txt`. The script then prints a time estimate and asks
for confirmation before starting.

## Checking methods

| Method | Throughput | Token | Notes |
| --- | --- | --- | --- |
| **GraphQL** | ~500,000 names/hr | required | 100 names per request; resolves users *and* organizations |
| **REST** | 5,000/hr with token, 60/hr without | optional | one request per name |
| **Web** | ~3,600/hr | none | requests `github.com/<name>` directly |

GraphQL is the default and by far the fastest. Rate limits are handled
automatically: the script reads `X-RateLimit-Reset` and sleeps until the window
reopens instead of failing.

## Output

Two files are written to the project root as the scan runs:

| File | Contents |
| --- | --- |
| `available.txt` | every name the scan reported as unregistered (weak signal) |
| `confirmed.txt` | names the real form confirmed as claimable (strong signal) |

Both are appended to and flushed immediately, so `Ctrl+C` never loses work. On
exit the summary tells you exactly where to resume — a prefix for generated
sets, a line number for file lists. Confirmed hits also trigger a desktop
notification (macOS) and a terminal bell.

Neither file is committed — both are gitignored as run output.

## Candidate lists

Ready-made lists in `usernames/`, for the "load from a text file" option:

| File | Names | Contents |
| --- | --- | --- |
| `all3chars.txt` | 47,952 | every valid 3-character name (letters, digits, hyphen) |
| `all4letters.txt` | 456,976 | every 4-letter combination |
| `commonwords.txt` | 2,241 | the most common English words |

The two exhaustive lists are just a convenience — the built-in generator
produces the same sets on demand. `commonwords.txt` is the interesting one:
short real words are the names people actually want, and the ones most likely
to be taken.

Entries that can never be GitHub usernames (symbols, apostrophes, non-Latin
characters, over 39 chars) are filtered out before any request is made, so no
quota is wasted.

## Notes

- Login state is stored in `pw-profile/`, so you only sign in once. **That
  directory holds your GitHub session cookies — it is gitignored and must never
  be committed or uploaded.** Anyone with those cookies can access your account
  without your password or 2FA.
- The script never submits the rename. The final click is always yours.
- Use a sensible rate limit. Hammering GitHub with hundreds of thousands of
  requests per hour is a good way to get your token or IP throttled.
