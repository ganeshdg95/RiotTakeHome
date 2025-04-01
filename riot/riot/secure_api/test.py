from django.test import Client, TestCase, tag
from django.urls import reverse
from pickle import dumps

from riot.api import api

@tag("API")
class APITestCase(TestCase):
    c: Client

    def setUp(self) -> None:
        super().setUp()
        self.c = Client()

    @tag("encrypt-decrypt")
    def test_encrypt_decrypt(self) -> None:
        """
        Test encrypting and decrypting a payload. Verify that both the original payload and the decrypted one contain the same fields
        and compares a serialized string of the properties.        
        """
        print("Testing encryption-decryption...")
        # Encryption
        data = {
            "json_field": {
                "name": "John Doe",
                "age": 30,
                "weight": 70.82,
                "contact": {
                    "email": "john@example.com",
                    "phone": "123-456-7890"
                }
            }
        }
        response = self.c.post(
            reverse(f"{api.urls_namespace}:encrypt"),
            data=data,
            content_type="application/json"
        )

        assert response.status_code == 200, f"response code: {response.status_code}, {response.json()}"
        print(f"Encrypt output: {response.json()}")

    	# Decryption
        enc_data = {"json_field": response.json()["encrypted_json"]}
        response = self.c.post(
            reverse(f"{api.urls_namespace}:decrypt"),
            data=enc_data,
            content_type="application/json"
        )

        assert response.status_code == 200, f"response code: {response.status_code}, {response.json()}"
        decrypted_data = response.json()
        print(f"Decrypt output: {decrypted_data}")

        assert len(decrypted_data["json_field"]) == len(data["json_field"]), "Decrypted data does not have the same number of fields"

        for key in data["json_field"]:
            if decrypted_data["json_field"].get(key, None):
                assert dumps(decrypted_data["json_field"][key]) == dumps(data["json_field"][key]), "decrypted data differs from input data"
            else:
                raise AssertionError("Missing key in decrypted data")
            
    @tag("partial-decrypt")
    def test_partial_decrypt(self) -> None:
        """
        Test decryption on a partially encrypted payload. Verify that properties that are not encrypted in the input payload do not get modified.
        """
        print("Testing partially encrypted input...")
        data = {
            "json_field": {
                "name": "John Doe",
                "age": "gARLHi4=",
                "weight": 70.82,
                "contact": {
                    "email": "john@example.com",
                    "phone": "123-456-7890"
                }
            }
        }
        ground_truth = {
            "json_field": {
                "name": "John Doe",
                "age": 30,
                "weight": 70.82,
                "contact": {
                    "email": "john@example.com",
                    "phone": "123-456-7890"
                }
            }
        }
        response = self.c.post(
            reverse(f"{api.urls_namespace}:decrypt"),
            data=data,
            content_type="application/json"
        )

        # Verify decryption
        assert response.status_code == 200, f"response code: {response.status_code}, {response.json()}"
        decrypted_data = response.json()
        print(f"Decrypt output: {decrypted_data}")

        # Compare to ground truth
        assert len(decrypted_data["json_field"]) == len(ground_truth["json_field"]), "Decrypted data does not have the same number of fields"

        for key in ground_truth["json_field"]:
            if decrypted_data["json_field"].get(key, None):
                assert dumps(decrypted_data["json_field"][key]) == dumps(ground_truth["json_field"][key]), "decrypted data differs from input data"
            else:
                raise AssertionError("Missing key in decrypted data")

    @tag("sign-verify")
    def test_sign_verify(self) -> None:
        """
        Test generating a signature and verifying its validity. Test behavior with an invalid payload-signature combination.
        """
        print("Testing signing and verifying...")
        # Sign
        data = {
            "json_field": {
                "message": "Hello World",
                "timestamp": 1616161616
            }
        }
        response = self.c.post(
            reverse(f"{api.urls_namespace}:sign"),
            data=data,
            content_type="application/json"
        )

        assert response.status_code == 200, f"response code: {response.status_code}, {response.json()}"
        print(response.json())
        signature = response.json()["signature"]

        
        # Verify signature using a payload where the order of the properties has been changed. Should output 204.
        signed_data = {
            "json_field": {
                "timestamp": 1616161616,
                "message": "Hello World"                
            },
            "signature": signature
        }
        response = self.c.post(
            reverse(f"{api.urls_namespace}:verify"),
            data=signed_data,
            content_type="application/json"
        )
        assert response.status_code == 204, f"response code: {response.status_code}, {response.json()}"

        # Verify signature using a payload where a property has been modified. Should output 400.
        tampered_data = {
            "json_field": {
                "message": "Goodbye World",
                "timestamp": 1616161616
            },
            "signature": signature
        }
        response = self.c.post(
            reverse(f"{api.urls_namespace}:verify"),
            data=tampered_data,
            content_type="application/json"
        )
        assert response.status_code == 400, f"response code: {response.status_code}, {response.json()}"