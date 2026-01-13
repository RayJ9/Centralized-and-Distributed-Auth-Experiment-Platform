import secrets
# from functools import reduce (Unused)

# SECP256R1 (Prime256v1) Curve Order
CURVE_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def eval_poly(poly, x, prime):
    val = 0
    for coeff in reversed(poly):
        val = (val * x + coeff) % prime
    return val

def extended_gcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def mod_inverse(k, p):
    g, x, y = extended_gcd(k, p)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % p

def lagrange_interpolate(x, x_s, y_s, prime):
    k = len(x_s)
    if k != len(y_s):
        raise ValueError("x_s and y_s must be same length")
        
    nums = [] 
    dens = [] 
    
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        
        num = 1
        den = 1
        
        for val in others:
            num = (num * (x - val)) % prime
            den = (den * (cur - val)) % prime
            
        nums.append(num)
        dens.append(den)
        
    den = reduce_prod(dens, prime)
    
    num_sum = 0
    for i in range(k):
        num = nums[i]
        den_others = (den * mod_inverse(dens[i], prime)) % prime
        term = (y_s[i] * num * den_others) % prime
        num_sum = (num_sum + term) % prime
        
    final_res = (num_sum * mod_inverse(den, prime)) % prime
    return final_res

def reduce_prod(lst, prime):
    res = 1
    for x in lst:
        res = (res * x) % prime
    return res

class ShamirSecretSharing:
    @staticmethod
    def split(secret_int, n, k, prime=CURVE_ORDER):
        """
        Split a secret integer into n shares with threshold k.
        """
        coeffs = [secret_int] + [secrets.randbelow(prime) for _ in range(k - 1)]
        
        shares = []
        for i in range(1, n + 1):
            val = eval_poly(coeffs, i, prime)
            shares.append((i, val))
        return shares

    @staticmethod
    def combine(shares, prime=CURVE_ORDER):
        """
        Recover secret from k shares.
        """
        x_s = [s[0] for s in shares]
        y_s = [s[1] for s in shares]
        return lagrange_interpolate(0, x_s, y_s, prime)
