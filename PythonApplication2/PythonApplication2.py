import math
import random

# 1) Обчислення функцій Ейлера та Мьобіуса. Знаходження найменшого спільного кратного.
def eulera(n):
    result = n
    p = 2
    while p * p <= n:
        if n % p == 0:
            while n % p == 0:
                n //= p
            result -= result // p
        p += 1
    if n > 1:
        result -= result // n
    return result

def Moebius(n):
    if n == 1:
        return 1
    prime_factors = 0
    p = 2
    while p * p <= n:
        if n % p == 0:
            n //= p
            prime_factors += 1
            if n % p == 0:
                return 0
        p += 1
    if n > 1:
        prime_factors += 1
    return -1 if prime_factors % 2 == 1 else 1

def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)

def lcm_list(numbers):
    lcm_result = 1
    for num in numbers:
        lcm_result = lcm(lcm_result, num)
    return lcm_result

# 2) Китайська теорема про лишки.
def ext_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = ext_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def chintheorem(n, a):
    prod = 1
    for ni in n:
        prod *= ni

    result = 0
    for ni, ai in zip(n, a):
        p = prod // ni
        _, x, _ = ext_gcd(p, ni)
        result += ai * x * p

    return result % prod

# 3) Символи Лежандра та Якобі.
def legendre_s(a, p):
    if a % p == 0:
        return 0
    elif pow(a, (p - 1) // 2, p) == 1:
        return 1
    else:
        return -1

def jacobi_s(a, n):
    if n <= 0 or n % 2 == 0:
        return None  # Або інше значення, що вказує на помилку
    # Решта коду функції...

    a %= n
    if a == 0:
        return 0
    if a == 1:
        return 1
    if a == 2:
        if n % 8 in [3, 5]:
            return -1
        else:
            return 1
    if a == n - 1:
        if n % 4 == 1:
            return 1
        else:
            return -1
    if math.gcd(a, n) > 1:
        return 0
    return jacobi_s(n % a, a)

# 4) Ро-алгоритм Полларда.
def pollard_alg(n, max_iterations=10000):
    if n % 2 == 0:
        return 2
    x = 2
    y = 2
    d = 1
    f = lambda x: (x ** 2 + 1) % n
    i = 0
    while d == 1 and i < max_iterations:
        x = f(x)
        y = f(f(y))
        d = math.gcd(abs(x - y), n)
        i += 1
    return d

# 5) Алгоритм «великий крок – малий крок».
def baby_step_giant_alg(g, h, p):
    m = int(p ** 0.5) + 1
    lookup = {}

    for j in range(m):
        value = pow(g, j, p)
        lookup[value] = j

    inv_g = pow(g, -m, p)
    current_h = h

    for i in range(m):
        if current_h in lookup:
            return i *             m + lookup[current_h]
        else:
            current_h = current_h * inv_g % p

    raise ValueError("Дискретний логарифм не знайдено.")

# 6) Алгоритм Чіпполи (Тонеллі-Шенкс) для знаходження дискретного квадратного кореня.
def tonel_shank_alg(a, p):
    if legendre_s(a, p) != 1:
        return None

    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1

    if s == 1:
        return pow(a, (p + 1) // 4, p)

    for z in range(2, p):
        if legendre_s(z, p) == -1:
            break

    c = pow(z, q, p)
    r = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)
    m = s

    while True:
        if t == 1:
            return r
        for i in range(1, m):
            if pow(t, 2**i, p) == 1:
                break
        b = pow(c, 2**(m - i - 1), p)
        r = (r * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

# 7) Алгоритм Соловея-Штрассена для перевірки чисел на простоту.
def soloway_strassen_alg(n, k=5):
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False

    for _ in range(k):
        a = random.randint(2, n - 1)
        x = jacobi_s(a, n)
        if x is None:
            continue  # Пропустити цю ітерацію, якщо jacobi_s повертає None
        y = pow(a, (n - 1) // 2, n)
        if y != x % n:
            return False
    return True


# 8) Криптосистема RSA.
def generate_rsa_key_cryptosystem(bits=256):
    p = random_prime(bits // 2)
    q = random_prime(bits // 2)
    n = p * q
    eulera_n = (p - 1) * (q - 1)

    e = random.randint(2, eulera_n - 1)
    while math.gcd(e, eulera_n) != 1:
        e = random.randint(2, eulera_n - 1)

    _, d, _ = ext_gcd(e, eulera_n)
    d %= eulera_n
    if d < 0:
        d += eulera_n

    return (e, n), (d, n)

def encryp_rsa_cryptosys(message, public_key):
    e, n = public_key
    return pow(message, e, n)

def decrypt_rsa_cryptosys(ciphertext, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)

# 9) Криптосистема Ель-Гамаля на еліптичних кривих.
class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def is_valid_point(self, x, y):
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if P == Q:
            if y1 == 0:
                return None
            l = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p)
        else:
            if x1 == x2:
                return None
            l = (y2 - y1) * pow(x2 - x1, -1, self.p)
        x3 = (l * l - x1 - x2) % self.p
        y3 = (l * (x1 - x3) - y1) % self.p
        return x3, y3

    def multiply(self, P, n):
        R = None
        m2 = P
        while n:
            if n & 1:
                R = self.add(R, m2)
            m2 = self.add(m2, m2)
            n >>= 1
        return R

def generate_elgamal_ec_keys(curve, G, n):
    x = random.randint(1, n - 1)
    H = curve.multiply(G, x)
    return (curve, G, H, n), x

def elgamal_ec_encrypt(message, public_key):
    curve, G, H, _ = public_key
    y = random.randint(1, curve.p - 1)
    C1 = curve.multiply(G, y)
    C2 = curve.add(message, curve.multiply(H, y))
    return C1, C2

def elgamal_ec_decrypt(ciphertext, private_key, public_key):
    curve, _, H, _ = public_key
    x = private_key
    C1, C2 = ciphertext
    S = curve.multiply(C1, x)
    M = curve.add(C2, (S[0], -S[1] % curve.p))
    return M

# Додаткові функції, необхідні для RSA та Ель-Гамаля.
def random_prime(bits):
    while True:
        number = random.getrandbits(bits)
        if soloway_strassen_alg(number):
            return number

# Приклад використання коду (необхідно вибрати або закоментувати конкретні розділи для тестування).
if __name__ == "__main__":
    # Тестування функцій Ейлера та Мьобіуса
    n_value = 42
    print(f"Euler's totient function φ({n_value}) = {eulera(n_value)}")
    print(f"Moebius function μ({n_value}) = {Moebius(n_value)}")

    # Тестування Китайської теореми про лишки
    n_values = [3, 4, 5]
    a_values = [2, 3, 1]
    print(f"Chinese Remainder Theorem: {chintheorem(n_values, a_values)}")

    # Тестування символів Лежандра та Якобі
    a_legendre, p_legendre = 3, 7
    print(f"Legendre symbol ({a_legendre}/{p_legendre}) = {legendre_s(a_legendre, p_legendre)}")
    a_jacobi, n_jacobi = 3, 11
    print(f"Jacobi symbol ({a_jacobi}/{n_jacobi}) = {jacobi_s(a_jacobi, n_jacobi)}")

    # Тестування ро-алгоритму Полларда
    n_pollard = 8051
    print(f"Pollard's Rho factorization of {n_pollard}: {pollard_alg(n_pollard)}")

    # Тестування алгоритму «великий крок – малий крок»
    g_bsgs, h_bsgs, p_bsgs = 2, 22, 29
    print(f"Discrete logarithm of {h_bsgs} in base {g_bsgs} mod {p_bsgs}: {baby_step_giant_alg(g_bsgs, h_bsgs, p_bsgs)}")

    # Тестування алгоритму Тонеллі-Шенкса
    a_tonelli, p_tonelli = 10, 13
    print(f"Tonelli-Shanks algorithm: Square root of {a_tonelli} mod {p_tonelli} is {tonel_shank_alg(a_tonelli, p_tonelli)}")

    # Тестування алгоритму Соловея-Штрассена
    n_solovay = 17
    print(f"Soloway-Strassen primality test for {n_solovay}: {soloway_strassen_alg(n_solovay)}")

    # Тестування криптосистеми RSA
    rsa_bits = 256
    public_key_rsa, private_key_rsa = generate_rsa_key_cryptosystem(rsa_bits)
    message_rsa = 42
    ciphertext_rsa = encryp_rsa_cryptosys(message_rsa, public_key_rsa)
    decrypted_message_rsa = decrypt_rsa_cryptosys(ciphertext_rsa, private_key_rsa)
    print(f"RSA: Original message: {message_rsa}, Encrypted: {ciphertext_rsa}, Decrypted: {decrypted_message_rsa}")

    # Тестування криптосистеми Ель-Гамаля на еліптичних кривих
    curve_ec = EllipticCurve(2, 3, 97) # Приклад параметрів еліптичної кривої
    generator_point_ec = (3, 6) # Приклад точки-генератора
    order_ec = 5
    public_key_ec, private_key_ec = generate_elgamal_ec_keys(curve_ec, generator_point_ec, order_ec)
    message_ec = (10, 22) # Приклад повідомлення у формі точки на кривій
    ciphertext_ec = elgamal_ec_encrypt(message_ec, public_key_ec)
    decrypted_message_ec = elgamal_ec_decrypt(ciphertext_ec, private_key_ec, public_key_ec)
    print(f"ElGamal EC: Original message: {message_ec}, Encrypted: {ciphertext_ec}, Decrypted: {decrypted_message_ec}")
