# URL Threat Checker

SYA201 course tool. It scores URLs with simple phishing heuristics.

## Run

```bash
python checker.py "http://192.168.1.10/banka-giris"
```

## Rules

- IP host, `@` sign, punycode, shorteners
- Risky TLDs, too many subdomains or hyphens
- Plain HTTP, login/bank words in path

## Verdict

- 0-2: looks clean, 3-4: suspicious, 5+: dangerous
