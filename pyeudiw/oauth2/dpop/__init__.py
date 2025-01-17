import base64
import hashlib
import logging
import uuid

from pyeudiw.jwk.schemas.public import JwkSchema
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.oauth2.dpop.exceptions import (
    InvalidDPoP,
    InvalidDPoPAth,
    InvalidDPoPKid
)
from pyeudiw.jwk.exceptions import KidError

from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.oauth2.dpop.schema import (
    DPoPTokenHeaderSchema,
    DPoPTokenPayloadSchema
)
from pyeudiw.tools.utils import iat_now

logger = logging.getLogger(__name__)


class DPoPIssuer:
    """
    Helper class for generate DPoP proofs.
    """

    def __init__(self, htu: str, token: str, private_jwk: dict):
        """
        Generates an instance of DPoPIssuer.

        :param htu: a string representing the htu value.
        :type htu: str
        :param token: a string representing the token value.
        :type token: str
        :param private_jwk: a dict representing the private JWK of DPoP.
        :type private_jwk: dict
        """
        self.token = token
        self.private_jwk = private_jwk
        self.signer = JWSHelper(private_jwk)
        self.htu = htu

    @property
    def proof(self):
        """
        Generates and returns the DPoP proof.

        :returns: The DPoP proof as a JWT.
        :rtype: str
        """
        
        # Define the payload for the DPoP proof
        data = {
            "jti": str(uuid.uuid4()),
            "htm": "GET",
            "htu": self.htu,
            "iat": iat_now(),
            "ath": base64.urlsafe_b64encode(hashlib.sha256(self.token.encode()).digest()).rstrip(b'=').decode()
        }
        jwt = self.signer.sign(
            data,
            protected={
                'typ': "dpop+jwt",
                'jwk': self.private_jwk.serialize()
            },
            kid_in_header=False
        )
        return jwt


class DPoPVerifier:
    """
    Helper class for validate DPoP proofs.
    """

    dpop_header_prefix = 'DPoP '

    def __init__(
        self,
        public_jwk: dict,
        http_header_authz: str,
        http_header_dpop: str,
    ):
        """
        Generate an instance of DPoPVerifier.

        :param public_jwk: a dict representing the public JWK of DPoP.
        :type public_jwk: dict
        :param http_header_authz: a string representing the authz value.
        :type http_header_authz: str
        :param http_header_dpop: a string representing the DPoP value.
        :type http_header_dpop: str

        :raises ValueError: if DPoP proof is not a valid JWT

        """
        self.public_jwk = public_jwk
        self.dpop_token = (
            http_header_authz.replace(self.dpop_header_prefix, '')
            if self.dpop_header_prefix in http_header_authz
            else http_header_authz
        )
        # If the jwk is invalid, raise an exception
        try:
            JwkSchema(**public_jwk)
        except Exception as e:
            logger.error(
                "Jwk validation error, "
                f"{e.__class__.__name__}: {e}"
            )
            raise ValueError("JWK schema validation error during DPoP init")

        # If the jwt is invalid, this will raise an exception
        try:
            decode_jwt_header(http_header_dpop)
        except UnicodeDecodeError as e:
            logger.error(
                "DPoP proof validation error, "
                f"{e.__class__.__name__}: {e}"
            )
            raise ValueError("DPoP proof is not a valid JWT")
        except Exception as e:
            logger.error(
                "DPoP proof validation error, "
                f"{e.__class__.__name__}: {e}"
            )
            raise ValueError("DPoP proof is not a valid JWT")
        self.proof = http_header_dpop

    @property
    def is_valid(self) -> bool:
        """Returns True if DPoP is valid."""
        return self.validate()

    def validate(self) -> bool:
        """
        Validates the content of DPoP.

        :raises InvalidDPoPKid: if the kid of DPoP is invalid.
        :raises InvalidDPoPAth: if the header's JWK is different from public_jwk's one.

        :returns: True if the validation is correctly executed, False otherwise
        :rtype: bool
        """
        jws_verifier = JWSHelper(jwks=[self.public_jwk])
        try:
            dpop_valid = jws_verifier.verify(self.proof)
        except KidError as e:
            raise InvalidDPoPKid(
                (
                    "DPoP proof validation error, "
                    f"kid does not match: {e}"
                )
            )
        except Exception as e:
            raise InvalidDPoP(
                "DPoP proof validation error, "
                f"{e.__class__.__name__}: {e}"
            )

        header = decode_jwt_header(self.proof)
        DPoPTokenHeaderSchema(**header)

        if header['jwk'] != self.public_jwk:
            raise InvalidDPoPAth((
                "DPoP proof validation error,  "
                "header['jwk'] != self.public_jwk, "
                f"{header['jwk']} != {self.public_jwk}"
            ))

        payload = decode_jwt_payload(self.proof)
        DPoPTokenPayloadSchema(**payload)

        _ath = hashlib.sha256(self.dpop_token.encode())
        _ath_b64 = base64.urlsafe_b64encode(
            _ath.digest()).rstrip(b'=').decode()
        proof_valid = _ath_b64 == payload['ath']
        return dpop_valid and proof_valid
