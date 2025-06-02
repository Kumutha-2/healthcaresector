from cryptography.fernet import Fernet
import re


def get_fernet_cipher(key: bytes) -> Fernet:
    return Fernet(key)

def encrypt_data(data: str, key: bytes) -> str:
    if not data: 
        return ""
    cipher = get_fernet_cipher(key)
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(token: str, key: bytes) -> str:
    if not token: 
        return ""
    cipher = get_fernet_cipher(key)
    try:
        return cipher.decrypt(token.encode()).decode()
    except Exception: 
        return token

def partial_encrypt_data(data: str, field_type: str, key: bytes) -> str:
    if not data:
        return ""

    if field_type == 'phone':
        if len(data) >= 4 and data.isnumeric(): 
            visible_part = data[-4:]
            part_to_encrypt = data[:-4]
            if not part_to_encrypt: 
                return data 
            encrypted_part = encrypt_data(part_to_encrypt, key)
            return f"ENC_PHONE|{encrypted_part}|{visible_part}"
        else:
            return encrypt_data(data, key) 

    elif field_type == 'email':
        if '@' in data:
            local_part, domain = data.rsplit('@', 1)
            encrypted_local = encrypt_data(local_part, key)
            return f"ENC_EMAIL|{encrypted_local}@{domain}"
        else:
            return encrypt_data(data, key) 
    else: 
        return encrypt_data(data, key)

def partial_decrypt_data(token: str, field_type: str, key: bytes) -> str:
    if not token:
        return ""

    try:
        if field_type == 'phone' and token.startswith("ENC_PHONE|"):
            parts = token.split('|', 2)
            if len(parts) == 3:
                _, encrypted_part, visible_part = parts
                decrypted_part = decrypt_data(encrypted_part, key)
                return f"{decrypted_part}{visible_part}"
            else: 
                return token 

        elif field_type == 'email' and token.startswith("ENC_EMAIL|"):
            prefix, main_part = token.split('|', 1)
            if '@' in main_part:
                encrypted_local, domain = main_part.rsplit('@', 1)
                decrypted_local = decrypt_data(encrypted_local, key)
                return f"{decrypted_local}@{domain}"
            else: 
                return token 
        
        return decrypt_data(token, key)
    except Exception:
        return token