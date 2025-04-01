from ninja import Schema
from typing import Dict, Any

class RawJson(Schema):
    """
    Used by several api methods as input or output. Validates any json payload

    Attributes:
        json_field (Dict[str,Any]): dictionary mapping strings to objects
    """
    json_field: Dict[str,Any]

class Encrypted(Schema):
    """
    Output for '/encrypt'. Validates a dictionary mapping keys to encrypted properties

    Attributes:
        encrypted_json (Dict[str,str]): dictionary mapping strings to strings
    """
    encrypted_json: Dict[str,str] # Field containing a generic dictionary with string keys

class Signature(Schema):
    """
    Output for '/sign'. Contains a single string.

    Attributes:
        signature (str ): signature string.
    """
    signature: str 

class Signed(RawJson, Signature):
    """
    Used as input to '/verify'. Mixin of RawJson and Signature schemas.

    Attributes:
        json_field (Dict[str,Any]): dictionary mapping strings to objects
        signature (str ): signature string.
    """
    pass