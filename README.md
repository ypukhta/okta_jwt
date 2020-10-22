# Async Okta Jwt

Async Okta JWT Access Token verifier for Python using cached JWKs.

Based on [okta_jwt](https://github.com/adithyasampatoor/okta_jwt) by Adithya Sampatoor

Link to PyPi - click [here](https://pypi.org/project/async-okta-jwt/)

## Installation

```python
	pip install async_okta_jwt
```

### Usage

To generate a token, you need to pass in `issuer`, `client_id`, `client_secret`, `username` and `password` as parameters
```python
	>>> from async_okta_jwt.jwt import generate_token
	>>> await generate_token(issuer, client_id, client_secret, username
, password)
```

This generates and returns Okta Access Token.


To Validate the Access Token, you need to pass in the `access_token`, `issuer`, `audience` and `client_ids` as parameters. You can pass in multiple Client IDs
```python
	>>> from async_okta_jwt.jwt import validate_token
	>>> await validate_token(access_token, issuer, audience, client_ids)
```

If the token is valid then it will return the payload.


## Running the tests

To run the unit tests, run

	$ python -m unittest

### Break down into tests

The unit tests pretty much covers all the main functionality of the package, like generating the token, Validating the token and Verifying Claims.

## Contributing

Bug reports and Pull Requests(PR's) are welcome on GitHub at
https://github.com/ypukhta/async_okta_jwt. This project is intended to be a safe, welcoming
 space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Authors

* **Adithya Sampatoor**

## License

The Library is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT)
