class VpTokenParser:
    """VpTokenParser is an interface that specify that an object is able to
    extract verifiable credentials from a VP token.
    """
    def get_credentials(self) -> dict:
        raise NotImplementedError

    def get_issuer_name(self) -> str:
        raise NotImplementedError


class VpTokenVerifier:
    """VpTokenVerifier is an interface that specify that an object is able to
    verify a vp token.
    The interface supposes that the verification process requires a public
    key (os the token issuer)
    """
    def is_expired(self) -> bool:
        raise NotImplementedError

    def is_revoked(self) -> bool:
        """
        :returns: if the credential is revoked
        """
        raise NotImplementedError

    def is_active(self) -> bool:
        return (not self.is_expired()) and (not self.is_revoked())

    def verify_signature(self) -> None:
        """
        Verify a token signature

        :raises InvalidSignatureException: if signature is invalid`
        """
        raise NotImplementedError

    def verify_challenge(self) -> None:
        """

        :raises []:
        """
        raise NotImplementedError
