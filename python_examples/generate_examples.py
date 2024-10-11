from freezegun import freeze_time
from itsdangerous import Signer, TimestampSigner
from itsdangerous.url_safe import URLSafeSerializer, URLSafeTimedSerializer

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

print()
print(f"UrlSafeSerializer examples {key=} {salt=}")
s = URLSafeSerializer(key, salt)
print("  'my string' -> ", s.dumps("my string"))
print("  dict(foo='bar') -> ", s.dumps(dict(foo='bar')))
print("  'aaaaaaaaaaaaaaaaaaa' -> ", s.dumps("aaaaaaaaaaaaaaaaaaa"))

print()
print(f"URLSafeTimedSerializer examples {key=} {salt=}")
s = URLSafeTimedSerializer(key, salt)
with freeze_time("2024-09-27T14:00:00Z"):
    print("  'my string' ->", s.dumps("my string"), "at time 2024-09-27T14:00:00Z")
    print("  dict(foo='bar') -> ", s.dumps(dict(foo='bar')), "at time 2024-09-27T14:00:00Z")
    print("  'aaaaaaaaaaaaaaaaaaa' -> ", s.dumps("aaaaaaaaaaaaaaaaaaa"), "at time 2024-09-27T14:00:00Z")
