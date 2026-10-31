def modular_exponentiation(base, exp, mod):
    if not all(isinstance(x, int) for x in (base, exp, mod)):
        raise TypeError("All inputs must be integers.")
    
    if exp < 0 or mod <= 0:
        raise ValueError("Exponent must be non-negative and modulus must be positive.")
    
    result = 1 % mod
    base = base % mod

    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp = exp // 2

    return result
