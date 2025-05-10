# 🔓 Minimalistic Implementations of RSA Attacks

## 📘 Introduction

This project provides simple, self-contained Python implementations of two classic cryptanalytic attacks on RSA: **Wiener's Attack** and **Pollard's p-1 Attack**. The goal is to demonstrate, in a minimalistic yet educational way, how certain RSA keys — despite appearing strong at first glance — can be vulnerable due to subtle cryptographic weaknesses.

All code is designed to be readable, educational, and focused on core logic rather than dependency-heavy frameworks. I wanted to understand and showcase **how these attacks work internally** by implementing them from scratch based on research and careful analysis of how the attacks are theoretically and practically constructed.

Two RSA public keys are included for demonstration. Both are **2048-bit** keys, seemingly strong and typical in format, but **deliberately constructed to be vulnerable** — one to Wiener's attack and one to Pollard's p-1 method. 

---

## 🗂️ Project Structure

```
.
├── wiener.py                     # Implements Wiener's attack
├── pollard.py                    # Implements Pollard's p-1 attack
├── vulnerable_to_wiener.pub      # 2048-bit RSA key vulnerable to Wiener’s attack
├── vulnerable_to_pollard.pub     # 2048-bit RSA key vulnerable to Pollard’s p-1 attack
└── README.md                     # This file
```

---

## 1️⃣ Wiener's Attack

### 📚 Background and Theory

**Wiener's attack** is a classic cryptanalytic method that targets RSA keys with **small private exponents** (`d`). It was introduced by **Michael J. Wiener in 1990**, in his paper _"Cryptanalysis of Short RSA Secret Exponents"_.

The attack hinges on a mathematical result: if `d < 1/3 * N^0.25` (where `N = p * q` is the RSA modulus), then `d` can be **efficiently recovered using continued fractions**. This is because the ratio `e/n` gives rise to convergents from the continued fraction expansion that closely approximate `d/k` for some small `k`.

#### ✅ Vulnerable Keys

Wiener's attack only works when:
- The RSA private exponent `d` is **unusually small**.
- This often happens in badly generated keys or intentionally weakened systems.
- Typical secure RSA keys avoid this vulnerability by choosing `d` large enough.

### 🧠 How It Works (Step-by-Step)

1. Compute the **continued fraction** expansion of `e/n`.
2. Generate all **convergents** `k_i/d_i` of the expansion.
3. For each pair `(k_i, d_i)`:
   - Check if `ed_i ≡ 1 mod k_i`.
   - Estimate `φ(n)` as `(ed_i - 1)/k_i`.
   - Try to solve for `(p, q)` by finding roots of the resulting quadratic.
4. If the roots multiply back to `n`, we’ve recovered `(p, q)` and `d`.

### 🧪 How My Script Works

Script: [`wiener.py`](./wiener.py)

- Uses `pycryptodome` to load a PEM-formatted RSA public key.
- Extracts `n` and `e` from the key.
- Applies continued fraction decomposition of `e/n`.
- Tests each convergent to see if it gives a valid private key.
- If successful, prints `p`, `q`, and `d`.

#### ▶️ Running the Script

```bash
python3 wiener.py vulnerable_to_wiener.pub
```

#### 🖼️ Example: Successful Attack Screenshot

📌 _Insert screenshot of successful run on `vulnerable_to_wiener.pub` here_

#### 🖼️ Example: Failed Attack Screenshot

📌 _Insert screenshot of running the script on `vulnerable_to_pollard.pub` and failing_

---

## 2️⃣ Pollard's p-1 Attack

### 📚 Background and Theory

**Pollard’s p-1 algorithm**, developed by **John Pollard in 1974**, is a factorization method that’s effective when one of the prime factors of `n = p*q` is such that `p−1` (or `q−1`) is **smooth**, i.e., composed only of **small prime factors**.

The algorithm is based on **Fermat’s Little Theorem**, where if `p` is a prime, then for any base `a`, `a^(p−1) ≡ 1 (mod p)`. The key insight is that if you raise `a` to a **multiple of p−1** modulo `n`, then the result will behave in a way that helps reveal `p` via a `gcd` computation.

#### ✅ Vulnerable Keys

Pollard’s p-1 works well if:
- One of the primes `p` or `q` has `p−1` that is **B-smooth** (i.e., all prime factors ≤ B).
- This sometimes happens when poor randomness is used to generate RSA keys.

### 🧠 How It Works (Step-by-Step)

1. Pick a base `a = 2`.
2. Iterate `i` from 2 to `B`:
   - Update `a = a^i mod n`.
   - Compute `g = gcd(a - 1, n)`.
3. If `g` is a non-trivial factor (`1 < g < n`), then:
   - `p = g`, `q = n // p`
4. Verify primality of `q`, and output `(p, q)` if valid.

### 🧪 How My Script Works

Script: [`pollard.py`](./pollard.py)

- Uses `pycryptodome` to read and parse the RSA public key file.
- Extracts the modulus `n`.
- Applies Pollard’s p-1 method with a default smoothness bound of `100000`.
- If it finds a non-trivial factor, it prints both primes.

#### ▶️ Running the Script

```bash
python3 pollard.py vulnerable_to_pollard.pub
```

#### 🖼️ Example: Successful Attack Screenshot

📌 _Insert screenshot of successful run on `vulnerable_to_pollard.pub` here_

#### 🖼️ Example: Failed Attack Screenshot

📌 _Insert screenshot of running the script on `vulnerable_to_wiener.pub` and failing_

---

## 🔐 Mitigation and Best Practices

### 🔒 How to Stay Safe

#### Against Wiener's Attack:
- Ensure the private exponent `d` is **not too small**.
- Use a **secure key generation library** that enforces proper bounds.
- The recommended lower bound is `d > n^0.25 / 3`.

#### Against Pollard's p-1 Attack:
- Avoid primes `p` or `q` where `p-1` is **smooth**.
- Use strong, random key generation routines (e.g., OpenSSL).
- Ensure both primes are **independently and unpredictably chosen**.

### ✅ General RSA Hygiene
- Always use at least 2048-bit keys.
- Use reputable, battle-tested libraries.
- Don’t try to “roll your own” key generation without deep knowledge.

---

## 🧪 Demo Keys

Two demo public keys are included:

- `vulnerable_to_wiener.pub`: 2048-bit key crafted to be breakable by Wiener's attack.
- `vulnerable_to_pollard.pub`: 2048-bit key crafted so `p-1` is B-smooth and breakable via Pollard's p-1 method.

Both look like standard secure keys but are intentionally weakened for demonstration purposes. You can test both scripts on both keys to observe success and failure scenarios.

---

## ⚙️ Requirements

Install dependencies via pip:

```bash
pip install pycryptodome
```

Scripts are fully compatible with **Python 3.8+** and run on **Windows**, **Linux**, or **macOS**.

---

## 📎 Closing Thoughts

These minimalist RSA attack implementations serve as a hands-on learning tool for understanding the dangers of misconfigured key parameters. While these vulnerabilities are well known in the cryptographic community, they **still surface in the wild** due to incorrect implementations or careless configurations.

Let these demos serve as a reminder: crypto is unforgiving — even one misstep can render your system breakable in milliseconds.

---

Enjoy hacking (ethically),  
_Matyas_
