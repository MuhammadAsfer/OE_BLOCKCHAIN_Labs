# OE Blockchain Labs 01-03 - student implementations

```
lab-01/txparser    Bitcoin tx parser            cd lab-01/txparser && uv sync && uv run pytest && uv run python -m txparser <hex>
lab-02             keys + crypto                cd lab-02 && uv sync && uv run pytest && uv run python -m crypto_lab [curve|ecdsa|wallet|pqc]
lab-03             consensus simulation         cd lab-03 && uv sync && uv run pytest && uv run python -m consensus [pow|pos|gossip] --workers 1
docs/              STUDY_GUIDE.md (read first), LAB01_RUNBOOK.md (Docker steps), REPORT_DRAFT.md
```
Status: all tests pass here (19 / 27 / 17). These are *my* tests built from the vectors in the companion page;
your course's reference suites (31 / 64 / 42) were not visible to me, so run them against this code and fix any API mismatch.
Not done: Docker/Bitcoin Core steps (yours), plots in the report, Hard practice items, "Beyond the labs", bonuses.
Lab 02's `test_bip84_address_vector` imports the Lab 01 parser by relative path (`../lab-01/txparser`); keep the folder layout.
