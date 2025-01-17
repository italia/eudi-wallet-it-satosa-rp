import binascii
from copy import deepcopy
import datetime
import json
import logging
from typing import Any, Literal, Union

from cryptojwt import JWS
from cryptojwt.jwk.jwk import key_from_jwk_dict

from pyeudiw.jwk.exceptions import KidError
from pyeudiw.jwk.jwks import find_jwk_by_kid, find_jwk_by_thumbprint
from pyeudiw.jwt.exceptions import JWEEncryptionError, JWSSigningError, JWSVerificationError
from pyeudiw.jwt.helper import JWHelperInterface, find_self_contained_key, is_payload_expired, serialize_payload, validate_jwt_timestamps_claims

from pyeudiw.jwk import JWK
from pyeudiw.jwt.utils import decode_jwt_header
from pyeudiw.tools.utils import iat_now

SerializationFormat = Literal["compact", "json"]

logger = logging.getLogger(__name__)

DEFAULT_HASH_FUNC = "SHA-256"

DEFAULT_SIG_KTY_MAP = {
    "RSA": "RS256",
    "EC": "ES256"
}

DEFAULT_SIG_ALG_MAP = {
    "RSA": "RS256",
    "EC": "ES256"
}

DEFAULT_ENC_ALG_MAP = {
    "RSA": "RSA-OAEP",
    "EC": "ECDH-ES+A256KW"
}

DEFAULT_ENC_ENC_MAP = {
    "RSA": "A256CBC-HS512",
    "EC": "A256GCM"
}

class JWSHelper(JWHelperInterface):
    """
    Helper class for working with JWS, extended to support SD-JWT.
    """

    def sign(
        self,
        plain_dict: Union[dict, str, int, None],
        protected: dict | None = None,
        unprotected: dict | None = None,
        serialization_format: SerializationFormat = "compact",
        signing_kid: str = "",
        kid_in_header: bool = True,
        **kwargs
    ) -> str:
        """Generate a signed JWS with the given payload and header.
        This method provides no guarantee that the input header is fully preserved,
        not does it guarantee that some optional but usually found header such
        as 'typ' and 'kid' are present.
        If the signing jwk has a kid claim, and the JWS header does not a have a kid claim,
        a kid matching the signing key 'kid' can be injected in the protected header
        by setting kid_in_header=True.

        Header claim 'alg' is always added as it is mandated by RFC7515
        and, if present, will be overridden with the actual 'alg' used for singing.
        This is done to make sure that untrusted alg values, such as none, cannot be used.

        The signing key is selected among the constructor jwks based on internal
        heuristics. The user can force with key he can attempt to use by
        setting signing_key, which will then be looked in the internal set
        of available keys.

        If the header already contains indication of a key, such as 'kid',
        'trust_chain' and 'x5c', there is no guarantee that the signing
        key to be used will be aligned with those header. We assume that is
        it responsibility of the class initiator to make those checks.

        :param plain_dict: The payload to be signed.
        :param protected: Protected header for the JWS.
        :param unprotected: Unprotected header for the JWS (only for JSON serialization).
        :param serialization_format: The format of the signature (compact or JSON).
        :param signing_kid: The key ID for signing.
        :param kid_in_header: If True, include the key ID in the token header.
        :param kwargs: Additional parameters for the signing process.

        :returns: The signed JWS token.
        :rtype: str

        :raises JWSSigningError: if there is any signing error, such as the signing
            key not being suitable for such a cryptographic operation
        """

        if protected is None:
            protected = {}
        if unprotected is None:
            unprotected = {}

        # Select the signing key
        signing_key = self._select_signing_key((protected, unprotected), signing_kid)  # TODO: check that singing key is either private or symmetric
        
        # Ensure the key ID in the header matches the signing key
        header_kid = protected.get("kid")
        signer_kid = signing_key.get("kid")
        if header_kid and signer_kid and (header_kid != signer_kid):
            raise JWSSigningError(f"token header contains a kid {header_kid} that does not match the signing key kid {signer_kid}")

        payload = serialize_payload(plain_dict)
        
         # Select a trusted algorithm and override header
        signing_alg: str = DEFAULT_SIG_KTY_MAP[JWK(signing_key).key.kty]
        protected["alg"] = signing_alg
        
         # Add "typ" header if not present
        if "typ" not in protected:
            protected["typ"] = "sd-jwt" if self.is_sd_jwt(plain_dict) else "JWT"

         # Include the signing key's kid in the header if required
        if kid_in_header and signer_kid:
            protected["kid"] = signer_kid # note that is actually redundant as the underlying library auto-update the header with the kid

        # this is a hack: if the header to be signed does NOT have kid and we do
        # not want to include it, then we must remove it from the signing kid
        # otherwise the signing library will auto insert it
        if not kid_in_header and not header_kid:
            signing_key = deepcopy(signing_key)
            signing_key.pop("kid", None)

        signer = JWS(payload, alg=signing_alg)
        keys = [key_from_jwk_dict(signing_key)]
        
        if serialization_format == "compact":
            try:
                signed = signer.sign_compact(
                    keys, protected=protected, **kwargs
                )
                return signed
            except Exception as e:
                raise JWSSigningError("Signing error: error in step", e)
        return signer.sign_json(
            keys=keys,
            headers=[(protected, unprotected)],
            flatten=True,
        )

    def _select_signing_key(self, headers: tuple[dict, dict], signing_kid: str = "") -> dict:
        if len(self.jwks) == 0:
            raise JWEEncryptionError("signing error: no key available for signature; note that {'alg':'none'} is not supported")
        # Case 0: key forced by the user
        if signing_kid:
            signing_key = self.get_jwk_by_kid(signing_kid)
            if not signing_kid:
                raise JWEEncryptionError(f"signing forced by using key with {signing_kid=}, but no such key is available")
            return signing_key.to_dict()
        # Case 1: only one key
        if (signing_key := self._select_signing_key_by_uniqueness()):
            return signing_key
        # Case 2: only one *singing* key
        if (signing_key := self._select_key_by_use(use="sig")):
            return signing_key
        # Case 3: match key by kid: this goes beyond what promised on the method definition
        if (signing_key := self._select_key_by_kid(headers)):
            return signing_key
        raise JWSSigningError("signing error: not possible to uniquely determine the signing key")

    def _select_signing_key_by_uniqueness(self) -> dict | None:
        if len(self.jwks) == 1:
            return self.jwks[0].to_dict()
        return None

    def _select_key_by_use(self, use: str) -> dict | None:
        candidate_signing_keys: list[dict] = []
        for key in self.jwks:
            key_d = key.to_dict()
            if use == key_d .get("use", ""):
                candidate_signing_keys.append(key_d)
        if len(candidate_signing_keys) == 1:
            return candidate_signing_keys[0]
        return None

    def _select_key_by_kid(self, headers: tuple[dict, dict]) -> dict | None:
        if not headers:
            return None
        if "kid" in headers[0]:
            kid = headers[0]["kid"]
        elif "kid" in headers[1]:
            kid = headers[1]["kid"]
        else:
            return None
        return find_jwk_by_kid([key.to_dict() for key in self.jwks], kid)

    def verify(self, jwt: str) -> (str | Any | bytes):
        """Verify a JWS with one of the initialized keys.
        Verification of tokens in JSON serialization format is not supported.

        :param jwt: The JWS token to be verified.
        :type jws: str

        :raises JWSVerificationError: if jws field is not in compact jws
            format or if the signature is invalid

        :returns: the decoded payload of the verified tokens.
        :rtype: str
        """

        try:
            header = decode_jwt_header(jwt)
        except (binascii.Error, Exception) as e:
            raise JWSVerificationError(
                f"Not a valid JWS format for the following reason: {e}"
            )

        verifying_key = self._select_verifying_key(header)
        if not verifying_key:
            raise JWSVerificationError(f"Verification error: unable to find matching public key for header {header}")

        # sanity check: kid must match if present
        if (expected_kid := header.get("kid")):
            obtained_kid = verifying_key.get("kid", None)
            if obtained_kid and (obtained_kid != expected_kid):
                raise JWSVerificationError(
                    KidError(
                        "unexpected verification state: found a valid verifying key,"
                        f"but its kid {obtained_kid} does not match token header kid {expected_kid}")
                )
        
        # Verify the JWS compact signature
        verifier = JWS(alg=header["alg"])
        msg: dict = verifier.verify_compact(jwt, [key_from_jwk_dict(verifying_key)])

        # Validate JWT claims
        try:
            validate_jwt_timestamps_claims(msg)
        except ValueError as e:
            raise JWSVerificationError(f"Invalid JWT claims: {e}")

        return msg

    def _select_verifying_key(self, header: dict) -> dict | None:
        available_keys = [key.to_dict() for key in self.jwks]

        # case 1: can be found by header
        if "kid" in header:
            if (verifying_key := find_jwk_by_kid(available_keys, header["kid"])):
                return verifying_key

        # case 2: the token is self contained, and the verification key matches one of the key in the whitelist
        if (self_contained_claims_key_pair := find_self_contained_key(header)):
            # check if the self contained key matches a trusted jwk
            used_claims, candidate_key = self_contained_claims_key_pair
            if hasattr(candidate_key, "thumbprint"):
                if (verifying_key := find_jwk_by_thumbprint(available_keys, candidate_key.thumbprint)):
                    return verifying_key
                else:
                    logger.error(f"Candidate key {candidate_key} does not have a thumbprint attribute.")
                    raise ValueError("Invalid key: missing thumbprint.")


        # case 3: if only one key and there is no header claim that can identitfy any key, than that MUST
        # be the only valid CANDIDATE key for signature verification
        if len(self.jwks) == 1:
            return self.jwks[0].to_dict()
        return None
    
    def is_sd_jwt(self, token: str) -> bool:
        """
        Determines if the provided JWT is an SD-JWT.

        :param token: The JWT token to inspect.
        :type token: str
        :returns: True if the token is an SD-JWT, False otherwise.
        :rtype: bool
        """
        if not token:
            return False
        
        try:
            # Decode the JWT header to inspect the 'typ' field
            header = decode_jwt_header(token)

            # Check if 'typ' field exists and is equal to 'sd-jwt'
            return header.get("typ") == "sd-jwt"
        except Exception as e:
            # Log or handle errors (optional)
            logger.warning(f"Unable to determine if token is SD-JWT: {e}")
            return False
