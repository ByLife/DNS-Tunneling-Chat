import rsa

def generate_keys():
    (pubkey, privkey) = rsa.newkeys(2048)
    
    with open('public_key.pem', 'wb') as f:
        f.write(pubkey.save_pkcs1('PEM'))
    
    with open('server_private_key.pem', 'wb') as f:
        f.write(privkey.save_pkcs1('PEM'))

    print("RSA keys generated and saved.")

    generate_keys()