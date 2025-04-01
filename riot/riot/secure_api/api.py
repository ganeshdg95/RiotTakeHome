
import re
from ninja import Router
from ninja.errors import HttpError
from django.http.request import HttpRequest

from .schema import RawJson, Encrypted, Signature, Signed
from .algorithms import Base64, HMAC

encryptionAlgo = Base64()
signatureAlgo = HMAC()

router = Router()

@router.post("/encrypt", response={200: Encrypted})
def encrypt(request: HttpRequest, data: RawJson):
    """
    Encrypts every property present in the json field of the input data at depth one.

    Parameters:
        request (HttpRequest): Contains metadata about the request.
        data (RawJson): Payload with a single 'json_field'. The 'json_field' contains a dictionary mapping strings to objects.

    Returns:
        response_code (int): HTTP response status code.
        response_data (Encrypted): Payload with a single 'encrypted_json' field. The 'encrypted_json' field contains a dictionary mapping strings to strings.
    """ 
    encrypted_data = {}
    for key, value in data.json_field.items(): # Loop over the properties in 'json_field'
        encrypted_data[key] = encryptionAlgo.encrypt(value)
    return {"encrypted_json": encrypted_data}

@router.post("/decrypt", response={200: RawJson})
def decrypt(request: HttpRequest, data: RawJson):
    """
    Check the input payload for encrypted strings and decrypt them. For each property at depth one, check if it is a string following a regular expression,
    if so decrypt it, otherwise let unchanged.

    Parameters:
        request (HttpRequest): Contains metadata about the request.
        data (RawJson): Payload with a single 'json_field'. The 'json_field' contains a dictionary mapping strings to objects.

    Returns:
        response_code (int): HTTP response status code.
        response_data (RawJson): Payload with a single 'json_field'. The 'json_field' contains a dictionary mapping strings to objects.
    """
    decrypted_data = {}
    for key, value in data.json_field.items():  # Loop over the properties in 'json_field'
        if isinstance(value, str): # Check if property is a string
            if re.fullmatch(encryptionAlgo.regex, value): # Check if property follows regex of the encryption algorithm
                decrypted_data[key] = encryptionAlgo.decrypt(value)
                continue
        decrypted_data[key] = value # Else add the property unchanged to the response data
    return {"json_field": decrypted_data}

@router.post("/sign", response={200: Signature})
def sign(request: HttpRequest, data: RawJson):
    """
    Generates a signature string taking the input payload as input. The secret key used for generating the signature is set as a property of the signature algorithm
    (for simplicity). The signature generated should be invariant to the order of the properties in the payload.

    Parameters:
        request (HttpRequest): Contains metadata about the request.
        data (RawJson): Payload with a single 'json_field'. The 'json_field' contains a dictionary mapping strings to objects.

    Returns:
        response_code (int): HTTP response status code.
        response_data (Signature): A signature string generated from the input payload.
    """ 
    signature = signatureAlgo.generate(data.json_field)
    return {"signature": signature}

@router.post("/verify", response={204: None, 400: None})
def verify(request: HttpRequest, data: Signed):
    """
    Verify signature using payload. The secret key used for verification is the same as that used for generation,
    and is set as a property of the signature algorithm (for simplicity). Respond with 204 if the signature is verified, otherwise respond with 400.

    Parameters:
        request (HttpRequest): Contains metadata about the request.
        data (RawJson): Payload with a single 'json_field'. The 'json_field' contains a dictionary mapping strings to objects.

    Returns:
        response_code (int): HTTP response status code.
    """ 
    if signatureAlgo.verify(data.json_field, data.signature):
        return 204, {}
    else:
        raise HttpError(400, "Access denied")