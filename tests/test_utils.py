import asynctest
from mock import patch
from ddt import ddt, data, unpack
from async_okta_jwt import utils
from async_okta_jwt.exceptions import JWTClaimsError, ExpiredSignatureError


@ddt
class TestUtils(asynctest.TestCase):
    now = 1545320000
    iat = 1545315000

    @unpack
    @data(
        (None, None, None, None, 'Access Token is required'),
        ('token', None, None, None, 'Issuer is required'),
        ('token', 'issuer', None, None, 'Audience is required'),
        ('token', 'issuer', 'audience', '', 'Client ID is required')
    )
    async def test_presence_of(self, access_token, issuer, audience,
                               client_ids,
                          error):
        with self.assertRaises(ValueError) as ctx:
            await utils.check_presence_of(access_token, issuer, audience,
                                      client_ids)
        self.assertEqual(error, str(ctx.exception))

    @unpack
    @data(
        ({'iss': 'invalid'}, 'issuer', True),
        ({'iss': 'issuer'}, 'issuer', False)
    )
    async def test_verify_iss(self, payload, issuer, raises):
        if raises:
            with self.assertRaises(JWTClaimsError) as ctx:
                await utils.verify_iss(payload, issuer)
            self.assertEqual('Invalid Issuer', str(ctx.exception))
        else:
            r = await utils.verify_iss(payload, issuer)
            self.assertIsNone(r)

    @unpack
    @data(
        ({'cid': 'invalid'}, 'client_id', True),
        ({'cid': 'client_id'}, 'client_id', False),
        ({'cid': 'client_id'}, ['client_id', 'other'], False)
    )
    async def test_verify_cid(self, payload, cid_list, raises):
        if raises:
            with self.assertRaises(JWTClaimsError) as ctx:
                await utils.verify_cid(payload, cid_list)
            self.assertEqual('Invalid Client', str(ctx.exception))
        else:
            r = await utils.verify_cid(payload, cid_list)
            self.assertIsNone(r)

    @unpack
    @data(
        ({}, 0, None, ''),
        ({'exp': ''}, 0, JWTClaimsError,
         'Expiration Time payload (exp) must be an integer.'),
        ({'exp': now}, 0, None, ''),
        ({'exp': now}, 1, None, ''),
        ({'exp': now - 1}, 0, ExpiredSignatureError, 'Token is expired.')
    )
    @patch('async_okta_jwt.utils.timegm')
    async def test_verify_exp(self, payload, leeway, error_t, error,
                              mocktimegm):
        mocktimegm.return_value = self.now
        if error_t:
            with self.assertRaises(error_t) as ctx:
                await utils.verify_exp(payload, leeway)
            self.assertEqual(error, str(ctx.exception))
        else:
            r = await utils.verify_exp(payload, leeway)
            self.assertIsNone(r)

    @unpack
    @data(
        ({}, None, ''),
        ({'aud': None}, None, 'Invalid claim format in token'),
        ({'aud': [None]}, None, 'Invalid claim format in token'),
        ({'aud': 'invalid'}, 'api://default', 'Invalid Audience')
    )
    async def test_verify_aud(self, payload, audience, error):
        if error:
            with self.assertRaises(JWTClaimsError) as ctx:
                await utils.verify_aud(payload, audience)
            self.assertEqual(error, str(ctx.exception))
        else:
            r = await utils.verify_aud(payload, audience)
            self.assertIsNone(r)

    @unpack
    @data(
        ({}, 0, False),
        ({'iat': iat}, 0, False),
        ({'iat': iat + 1}, 0, True)
    )
    @patch('async_okta_jwt.utils.timegm')
    async def test_verify_iat(self, payload, leeway, raises, mocktimegm):
        mocktimegm.return_value = self.iat
        if raises:
            with self.assertRaises(JWTClaimsError) as ctx:
                await utils.verify_iat(payload, leeway)
            self.assertEqual('Invalid Issued At(iat) Time', str(ctx.exception))
        else:
            r = await utils.verify_iat(payload, leeway)
            self.assertIsNone(r)
