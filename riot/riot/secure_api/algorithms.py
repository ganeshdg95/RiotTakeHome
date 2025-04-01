from typing import Any
from abc import ABC, abstractmethod
from pickle import dumps, loads
import json
import hashlib

class AbstractEncryptionAlgo(ABC):
    """
    Abstract method defining the requirements for an encryption algorithm.
    """
    @property
    @abstractmethod
    def regex(self):
        pass

    @abstractmethod
    def encrypt(self, data: Any) -> str:
        pass

    @abstractmethod
    def decrypt(self, string: str) -> Any:
        pass

class Base64(AbstractEncryptionAlgo):
    """
    Implementation of the Base64 algorithm.

    Code taken and modified from https://gist.github.com/trondhumbor/ce57c0c2816bb45a8fbb
    """

    regex = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"

    CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    def chunk(self, data, length):
        return [data[i:i+length] for i in range(0, len(data), length)]

    def encrypt(self, data: Any) -> str:
        byteArray = dumps(data)

        override = 0
        if len(byteArray) % 3 != 0:
            override = (len(byteArray) + 3 - len(byteArray) % 3) - len(byteArray)
        byteArray += b"\x00"*override

        threechunks = self.chunk(byteArray, 3)

        binstring = ""
        for chunk in threechunks:
            for x in chunk:
                binstring += "{:0>8}".format(bin(x)[2:])

        sixchunks = self.chunk(binstring, 6)

        outstring = ""
        for element in sixchunks:
            outstring += self.CHARS[int(element, 2)]

        if override > 0:
            outstring = outstring[:-override] + "="*override
        return outstring

    def decrypt(self, string: str) -> Any:
        override = string.count("=")
        string = string.replace("=", "A")
        
        binstring = ""
        for char in string:
            binstring += "{:0>6b}".format(self.CHARS.index(char))

        eightchunks = self.chunk(binstring, 8)
        
        outbytes = b""
        for chunk in eightchunks:
            outbytes += bytes([int(chunk, 2)])

        if override > 0:
            outbytes = outbytes[:-override]
        return loads(outbytes)
    
class AbstractSignatureAlgo(ABC):
    """
    Abstract method defining the requirements for a signature algorithm.
    """
    @property
    @abstractmethod
    def secret(self):
        pass

    @abstractmethod
    def generate(self, data: Any) -> str:
        pass

    @abstractmethod
    def verify(self, data: Any, string: str) -> bool:
        pass

class HMAC(AbstractSignatureAlgo):
    """
    Implementation of the HMAC algorithm using sha256 and a fixed secret key.
    The fixed secret key is used for simplicity.
    A better solution would use asymmetric encrytion to prevent exchanging the key.
    """
    secret = "confidential_string"
    
    def generate(self, data: Any) -> str:
        # Convert dictionary to a JSON string in a sorted manner
        serialized_data = json.dumps(data, sort_keys=True).encode('utf-8')
        key = self.secret.encode('utf-8')

        block_size = 64
        
        # Ensure the key is the correct length
        if len(key) > block_size:
            key = hashlib.sha256(key).digest()
        if len(key) < block_size:
            key = key.ljust(block_size, b'\x00')
        
        # Create outer and inner paddings
        o_key_pad = bytes((x ^ 0x5C) for x in key)
        i_key_pad = bytes((x ^ 0x36) for x in key)
        
        # Perform the HMAC computation manually
        inner_hash = hashlib.sha256(i_key_pad + serialized_data).digest()
        return hashlib.sha256(o_key_pad + inner_hash).hexdigest()

    def verify(self, data: Any, string: str) -> bool:
        return self.generate(data=data) == string