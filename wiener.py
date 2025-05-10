#!/usr/bin/env python3

""" A script for RSA private exponent recovery via Wiener's attack.
It reads a PEM-formatted RSA public key file, extracts the modulus (n)
and exponent (e), and applies a continued-fraction-based method to recover
a small private exponent (d) when vulnerable. """

import argparse
import logging
import math
import sys

from Crypto.PublicKey import RSA  # Requires pycryptodome or similar

# Load modulus (n) and exponent (e) from a PEM file
def load_public_components(path):
    logging.info("Attempting to read public key from '%s'", path)
    try:
        pem_data = open(path, 'r').read()
        key = RSA.import_key(pem_data)
        logging.debug("Key loaded successfully")
        return key.n, key.e
    except Exception as err:
        logging.error("Could not load key: %s", err)
        sys.exit(1)

# Compute the continued fraction expansion of a/b
def decompose_continued_fraction(a, b):
    logging.debug("Starting continued-fraction decomposition")
    quotients = []
    while b:
        q = a // b
        quotients.append(q)
        logging.debug("Quotient: %d (remainder step)", q)
        a, b = b, a - q * b
    logging.debug("Completed decomposition: %s", quotients)
    return quotients

# Yield (numerator, denominator) pairs for each continued fraction convergent
def convergent_pairs(quotients):
    h_prev2, h_prev1 = 0, 1
    k_prev2, k_prev1 = 1, 0
    for idx, q in enumerate(quotients):
        h = q * h_prev1 + h_prev2
        k = q * k_prev1 + k_prev2
        logging.debug("Convergent %d: numerator=%d, denominator=%d", idx, h, k)
        yield h, k
        h_prev2, h_prev1 = h_prev1, h
        k_prev2, k_prev1 = k_prev1, k

# Check if x is a perfect square
def is_perfect_square(x):
    if x < 0:
        return False
    root = math.isqrt(x)
    result = root * root == x
    logging.debug("Testing square for %d: %s", x, result)
    return result

# Perform Wiener's attack to find d given n and e
def wiener_attack(n, e):
    logging.info("Beginning Wiener's attack on (n=%d, e=%d)", n, e)

    # Step 1: continued fraction of e/n
    cf = decompose_continued_fraction(e, n)

    # Step 2: test each convergent
    for idx, (k_i, d_i) in enumerate(convergent_pairs(cf)):
        logging.debug("Testing candidate #%d: k=%d, d=%d", idx, k_i, d_i)
        if k_i == 0:
            continue

        # Check if (e * d - 1) divisible by k
        if (e * d_i - 1) % k_i != 0:
            continue

        phi_est = (e * d_i - 1) // k_i
        s = n - phi_est + 1
        disc = s * s - 4 * n

        # Discriminant must be perfect square
        if not is_perfect_square(disc):
            continue

        t = math.isqrt(disc)
        p = (s + t) // 2
        q = (s - t) // 2

        # Verify factorization
        if p * q == n:
            logging.info("Private exponent recovered at iteration %d", idx)
            return int(p), int(q), int(d_i)

    logging.warning("Wiener attack did not succeed on given key.")
    return None, None, None


def main():
    # Configure logging here
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
        datefmt="%H:%M:%S"
    )

    parser = argparse.ArgumentParser(
        description="Recover small RSA private exponent via Wiener's attack"
    )
    parser.add_argument(
        "keyfile",
        help="Path to the PEM-formatted RSA public key file"
    )
    args = parser.parse_args()

    print()
    n, e = load_public_components(args.keyfile)
    p, q, d = wiener_attack(n, e)

    if d:
        print("\nAttack Successful!\n")
        print(f"Prime factors:\n p = {p}\n q = {q}")
        print(f"Private exponent:\n d = {d}\n")
    else:
        print("\nAttack failed: no valid private exponent found.\n")


if __name__ == "__main__":
    main()