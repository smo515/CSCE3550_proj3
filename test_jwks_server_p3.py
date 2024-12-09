import unittest
from jwks_server_p3 import app, init_db, generate_key_pair, get_key_from_db

class TestJWKSServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db(True)
        cls.app = app.test_client()
        print(f"set up class")

    def test_key_generation_and_retrieval(self):
        test_kid = generate_key_pair(30)
        kid, private_key, exp = get_key_from_db()
        self.assertIsNotNone(kid)
        self.assertIsNotNone(private_key)
        self.assertEqual(test_kid, kid)

    def test_jwks_endpoint(self):
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('keys', data)
        self.assertIsInstance(data['keys'], list)

    def test_user_registration(self):
        response = self.app.post('/register', json={
            "username": "test_user",
            "email": "test@example.com"
        })
        self.assertEqual(response.status_code, 201)
        self.assertIn('password', response.get_json())

    def test_authentication(self):
        generate_key_pair(30)
        kid, private_key, exp = get_key_from_db()
        self.app.post('/register', json={
            "username": "auth_test_user",
            "email": "authtest@example.com"
        })
        response = self.app.post('/auth', json={
            "username": "auth_test_user"
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.get_json())

if __name__ == '__main__':
    unittest.main()
