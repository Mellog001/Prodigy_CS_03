import re
import math
import random
import string

def assess_password_strength(password: str):
    criteria = {
        'length': len(password) >= 12,
        'lower': bool(re.search(r'[a-z]', password)),
        'upper': bool(re.search(r'[A-Z]', password)),
        'number': bool(re.search(r'[0-9]', password)),
        'special': bool(re.search(r'[^A-Za-z0-9]', password)),
        'sequence': not detect_sequences(password)
    }

    pool_size = estimate_pool_size(password)
    bits = bits_of_entropy(pool_size, len(password))

    # Apply penalties for missing criteria
    adjusted = bits
    if not criteria['length']: adjusted -= 8
    if not criteria['lower']: adjusted -= 3
    if not criteria['upper']: adjusted -= 3
    if not criteria['number']: adjusted -= 3
    if not criteria['special']: adjusted -= 3
    if not criteria['sequence']: adjusted -= 6
    if re.search(r'password|1234|qwerty|letmein', password, re.I):
        adjusted = min(adjusted, 10)

    score_label = score_from_entropy(adjusted)['label']

    suggestions = []
    if not password:
        suggestions.append('Start by typing a password to see suggestions.')
    else:
        if not criteria['length']: suggestions.append('Make it at least 12 characters long.')
        if not criteria['lower']: suggestions.append('Add lowercase letters.')
        if not criteria['upper']: suggestions.append('Add uppercase letters.')
        if not criteria['number']: suggestions.append('Include numbers.')
        if not criteria['special']: suggestions.append('Include special characters like !@#$%')
        if not criteria['sequence']: suggestions.append('Avoid long repeated or sequential characters (e.g., 1111, abcd).')
        if re.search(r'password|1234|qwerty|letmein', password, re.I):
            suggestions.append('Avoid common words or keyboard patterns.')
        if not suggestions:
            suggestions.append('Looks good — consider using a password manager and unique passwords per site.')

    return {
        'strength': score_label,
        'entropy_bits': round(bits, 2),
        'criteria': criteria,
        'suggestions': suggestions
    }

def detect_sequences(s):
    if not s or len(s) < 4:
        return False
    if re.search(r'(.)\1{3,}', s):
        return True
    for i in range(len(s) - 3):
        chunk = s[i:i+4]
        asc = all(ord(chunk[j]) == ord(chunk[j-1]) + 1 for j in range(1, len(chunk)))
        desc = all(ord(chunk[j]) == ord(chunk[j-1]) - 1 for j in range(1, len(chunk)))
        if asc or desc:
            return True
    return False

def estimate_pool_size(s):
    pool = 0
    if re.search(r'[a-z]', s): pool += 26
    if re.search(r'[A-Z]', s): pool += 26
    if re.search(r'[0-9]', s): pool += 10
    if re.search(r'[^A-Za-z0-9]', s): pool += 33
    return max(pool, 10)

def bits_of_entropy(pool, length):
    return length * math.log2(pool) if pool > 0 else 0

def score_from_entropy(bits):
    if bits < 28: return {'label': 'Very weak', 'value': 10}
    if bits < 36: return {'label': 'Weak', 'value': 28}
    if bits < 60: return {'label': 'Reasonable', 'value': 56}
    if bits < 128: return {'label': 'Strong', 'value': 80}
    return {'label': 'Very strong', 'value': 100}

def generate_strong_password(length=18):
    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    specials = '!@#$%^&*()-_=+[]{};:,.<>/?~'

    pw = [
        random.choice(lowers),
        random.choice(uppers),
        random.choice(digits),
        random.choice(specials)
    ]

    all_chars = lowers + uppers + digits + specials
    pw += [random.choice(all_chars) for _ in range(length - 4)]
    random.shuffle(pw)
    return ''.join(pw)

if __name__ == '__main__':
    password = input('Enter a password to test: ')
    result = assess_password_strength(password)

    print(f"\nStrength: {result['strength']}")
    print(f"Entropy: {result['entropy_bits']} bits")
    print('Criteria:')
    for k, v in result['criteria'].items():
        print(f"  {k}: {'✓' if v else '✗'}")
    print('\nSuggestions:')
    for s in result['suggestions']:
        print(' -', s)

    print('\nGenerate strong password example:', generate_strong_password())
    # End of Password_checker.py
    
