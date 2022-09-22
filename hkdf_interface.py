import hkdf.hkdf as hkdf


def hkdf_extract(salt, input_key_material):
    if isinstance(input_key_material, str):
        input_key_material = bytes(input_key_material, 'utf-8')
    return hkdf.hkdf_extract(salt, input_key_material)


def hkdf_expand(pseudo_random_key, info, length=32):
    if isinstance(info, str):
        info = bytes(info, 'utf-8')
    return hkdf.hkdf_expand(pseudo_random_key, info, length)
