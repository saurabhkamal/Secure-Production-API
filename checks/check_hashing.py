import time             # to measure how slow bcrypt is

from app.security import hash_password, verify_password

hash1 = hash_password("alice-pass-123")             # hash the same password
hash2 = hash_password("alice-pass-123")             # twice

print("Hash 1:", hash1)
print("Hash 2:", hash2)
print("Same password, different hashes:", hash1 != hash2)   # salt makes them differ
print("Length:", len(hash1))                                # always 60

print("Correct password:", verify_password("alice-pass-123", hash1))  # True
print("Wrong password:", verify_password("wrong-pass", hash1))        # False
print("Works with hash 2:", verify_password("alice-pass-123", hash2)) # True: salt is inside each hash

start = time.perf_counter()                 # start a stopwatch
hash_password("timing-test")                # one hash
print(f"One hash took {(time.perf_counter() - start) * 1000:.0f} ms") # deliberately slow
