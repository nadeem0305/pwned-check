# pwned-check

**Live:** https://pwned-check.vercel.app (runs entirely in your browser; same k-anonymity check)

Check whether a password has shown up in a data breach, without sending the password anywhere.

It hashes the password with SHA-1 and sends only the first 5 characters of the hash to the
[Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API. The API returns every
breached hash starting with those 5 characters, and the match happens on your machine. Responses are
padded so their size doesn't leak anything either.

```
go install github.com/nadeem0305/pwned-check@latest
pwned-check            # prompts, input hidden
```

Exit status: `0` not found, `1` found, `2` error. Piped input works too, but avoid `echo password |`
since it lands in your shell history.
