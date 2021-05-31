import httpx
from jose import jwk, jwt
from jose.utils import base64url_decode
from async_okta_jwt.utils import verify_exp, verify_aud, check_presence_of, verify_iat, verify_iss, verify_cid


JWKS_CACHE = {}

# Generates Okta Access Token
async def generate_token(issuer, client_id, client_secret, username, password,
                    scope='openid'):
    """For generating a token, you need to pass in the Issuer,
    Client ID, Client Secret, Username and Password
    """
    auth = httpx.BasicAuth(client_id, client_secret)

    headers = {
        'Accept':       'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # grant_type is gonna be constant
    payload = {
        "username":   username,
        "password":   password,
        "scope":      scope,
        "grant_type": "password"
    }

    url = "{}/v1/token".format(issuer)

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, data=payload, headers=headers,
                                   auth=auth)

        # Consider any status other than 2xx an error
        if not response.status_code // 100 == 2:
            raise Exception(response.text, response.status_code)

        return_value = response.json()

        if 'access_token' not in return_value:
            raise Exception("no access_token in response from /token endpoint", 401)

        access_token = return_value['access_token']

        return access_token
    except httpx.RequestError as e:
        # A serious problem happened, like an SSLError or InvalidURL
        raise Exception("Error: {}".format(str(e)))


# Verifies Claims
async def verify_claims(payload, issuer, audience, cid_list):
    """ Validates Issuer, Client IDs, Audience
    Issued At time and Expiration in the Payload
    """
    await verify_iss(payload, issuer)
    await verify_cid(payload, cid_list)
    await verify_aud(payload, audience)
    await verify_exp(payload)
    await verify_iat(payload)


# Validates Token
async def validate_token(access_token, issuer, audience, client_ids):
    # Client ID's list
    cid_list = []

    if not isinstance(client_ids, list):
        cid_list = client_ids.split(',')
    else:
        cid_list = client_ids

    await check_presence_of(access_token, issuer, audience, cid_list)

    # Decoding Header & Payload from token
    header = jwt.get_unverified_header(access_token)
    payload = jwt.get_unverified_claims(access_token)

    # Verifying Claims
    await verify_claims(payload, issuer, audience, cid_list)

    # Verifying Signature
    jwks_key = await fetch_jwk_for(header, payload)
    key      = jwk.construct(jwks_key)
    message, encoded_sig = access_token.rsplit('.', 1)
    decoded_sig = base64url_decode(encoded_sig.encode('utf-8'))

    valid = key.verify(message.encode(), decoded_sig)

    # If the token is valid, it returns the payload 
    if valid == True:
        return payload
    else:
        raise Exception('Invalid Token')


# Extract public key from metadata's jwks_uri using kid
async def fetch_jwk_for(header, payload):
    # Extracting kid from the Header
    if 'kid' in header:
        kid = header['kid']
    else:
        raise ValueError('Token header is missing "kid" value')

    global JWKS_CACHE

    # If there is a matching kid, it wont fetch for kid from the server again
    if JWKS_CACHE:
        if kid in JWKS_CACHE:
            return JWKS_CACHE[kid]

    # Fetching jwk
    jwks = await fetch_metadata_for(payload)
    url = jwks['jwks_uri']

    try:
        async with httpx.AsyncClient() as client:
            jwks_response = await client.get(url)

        # Consider any status other than 2xx an error
        if not jwks_response.status_code // 100 == 2:
            raise Exception(jwks_response.text, jwks_response.status_code)
    except httpx.RequestError as e:
        # A serious problem happened, like an SSLError or InvalidURL
        raise Exception("Error: {}".format(str(e)))

    jwks = list(filter(lambda x: x['kid'] == kid, jwks_response.json()['keys']))
    if not len(jwks):
        raise Exception("Error: Could not find jwk for kid: {}".format(kid))
    jwk = jwks[0]

    # Adding JWK to the Cache
    JWKS_CACHE[kid] = jwk

    return jwk


async def fetch_metadata_for(payload):
    # Extracting client_id and issuer from the Payload
    client_id = payload['cid']
    issuer    = payload['iss']

    # Preparing URL to get the metadata
    url = "{}/.well-known/oauth-authorization-server?client_id={}".format(issuer, client_id)

    try:
        async with httpx.AsyncClient() as client:
            metadata_response = await client.get(url)

        # Consider any status other than 2xx an error
        if not metadata_response.status_code // 100 == 2:
            raise Exception(metadata_response.text, metadata_response.status_code)

        json_obj = metadata_response.json()
        return json_obj

    except httpx.RequestError as e:
        # A serious problem happened, like an SSLError or InvalidURL
        raise Exception("Error: {}".format(str(e)))
