#!/usr/bin/env python3

""" A script for RSA modulus factorization via Pollard's p-1 attack.
It reads a PEM-formatted RSA public key file, extracts the modulus (n),
and attempts to find a non-trivial factor using Pollard's p-1 method with an
adjustable smoothness bound. """

import argparse
import logging
import math
import sys

from Crypto.PublicKey import RSA # Requires pycryptodome
from Crypto.Util.number import isPrime # Primality test

#Load modulus (n) from a PEM file
def load_public_components(path):
    logging.info("Loading public key from '%s'", path)
    try:
        data = open(path, 'r').read()
        key = RSA.import_key(data)
        logging.debug("PEM data parsed successfully")
        return key.n
    except Exception as exc:
        logging.error("Failed to load key: %s", exc)
        sys.exit(1)

#Attempt Pollard's p-1 factorization on `modulus` with smoothness bound B
def execute_pollards_p_minus_one(modulus: int, bound: int = 100_000) -> tuple[int, int] | tuple[None, None]:
    logging.info("Beginning Pollard's p-1 with bound B=%d", bound)
    a = 2

    for i in range(2, bound):
        a = pow(a, i, modulus)
        g = math.gcd(a - 1, modulus)
        logging.debug("Iteration %d: gcd(a-1, n) = %d", i, g)

        if 1 < g < modulus:
            logging.info("Non-trivial factor found: p = %d", g)
            q = modulus // g
            if isPrime(q):
                logging.info("Verified q = %d is prime", q)
                return int(g), int(q)
            else:
                logging.warning("q = %d is not prime; aborting this path", q)
                return None, None

    logging.warning("No factor found within bound B=%d", bound)
    return None, None


def main():
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
        datefmt="%H:%M:%S"
    )

    parser = argparse.ArgumentParser(
        description="Factor RSA modulus via Pollard's p-1 attack"
    )
    parser.add_argument(
        "keyfile",
        help="Path to PEM-formatted RSA public key"
    )
    args = parser.parse_args()

    print()
    n = load_public_components(args.keyfile)
    p, q = execute_pollards_p_minus_one(n)

    if p and q:
        print("\nFactorization Successful!\n")
        print(f"p = {p}")
        print(f"q = {q}\n")
    else:
        print("\nFactorization failed: no valid factors found.\n")

if __name__ == "__main__":
    main()