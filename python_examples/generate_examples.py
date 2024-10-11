from freezegun import freeze_time
from itsdangerous import Signer, TimestampSigner

key = "secret_key"
salt = "salt"

print(f"Signer examples {key=} {salt=}")
s = Signer(key, salt)
print("  'my string' ->", s.sign("my string"))
print("  'aaaaaaaaaaaaaaaa' ->", s.sign("aaaaaaaaaaaaaaaa"))
print()

print(f"TimestampSigner examples {key=} {salt=}")
s = TimestampSigner(key, salt)
with freeze_time("2024-09-27T14:00:00Z"):
    print("  'my string' ->", s.sign("my string"), "at time 2024-09-27T14:00:00Z")
with freeze_time("2024-09-27T15:00:00Z"):
    print("  'my string' ->", s.sign("my string"), "at time 2024-09-27T15:00:00Z")
