class AuthRespParsingException(Exception):
    """Raised when the http request corresponding to an authorization response is malformed.
    """
    pass


class AuthRespValidationException(Exception):
    """Raised when the http request corresponding to an authorization response is well formed,
    but not valid (for example, it might be wrapped in an expired token).
    """
    pass


class KIDNotFound(Exception):
    """
    Raised when kid is not present in the public key dict
    """


class VPSchemaException(Exception):
    pass


class VPNotFound(Exception):
    pass


class VPInvalidNonce(Exception):
    pass


class NoNonceInVPToken(Exception):
    """
    Raised when a given VP has no nonce
    """


class InvalidVPToken(Exception):
    """
    Raised when a given VP is invalid
    """


class InvalidVPKeyBinding(InvalidVPToken):
    """Raised when a given VP contains a proof of possession key binding with
    wrong parameters.
    """


class InvalidVPSignature(InvalidVPKeyBinding):
    """Raised when a VP contains a proof of possession key binding and
    its signature verification failed.
    """


class RevokedVPToken(Exception):
    """
    Raised when a given VP is revoked
    """


class VPFormatNotSupported(Exception):
    """
    Raised when a given VP format is not supported
    """
