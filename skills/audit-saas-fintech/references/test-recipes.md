# Test recipes

## Cross-tenant IDOR (pytest/requests style)
```python
def test_tenant_b_cannot_read_tenant_a_invoice(client, tenant_a_token, tenant_b_token):
    inv = client.post("/invoices", json={"amount_cents": 1000}, headers=auth(tenant_a_token)).json()
    for method in ("get", "put", "delete"):
        r = getattr(client, method)(f"/invoices/{inv['id']}", headers=auth(tenant_b_token))
        assert r.status_code in (403, 404)
```
## Double-spend race (50 parallel withdrawals)
```python
async def test_no_overdraw(api, account_with_100_cents):
    results = await asyncio.gather(*[api.post("/withdrawals", json={"amount_cents": 100}, headers={"Idempotency-Key": str(uuid4())}) for _ in range(50)])
    assert sum(r.status == 201 for r in results) == 1 and balance(account_with_100_cents) == 0
```
## Idempotent replay
Same `Idempotency-Key` twice → identical response, one ledger entry; same key + different body → 422.
## Ledger invariant (property test, hypothesis)
For any sequence of valid operations: `sum(debits) == sum(credits)` and `balance == sum(entries)`; no negative balance unless overdraft is configured.
## Webhook authenticity
Replay an old signed payload (timestamp too old → reject); tamper one byte → reject; same event id twice → processed once.
