from copy import deepcopy
import datetime
import hashlib
import json
import logging
from typing import Any

from pydantic import ValidationError
from satosa.context import Context
from satosa.internal import AuthenticationInformation, InternalData
from satosa.response import Redirect

from pyeudiw.openid4vp.authorization_response import AuthorizeResponsePayload, DirectPostJwtJweParser, DirectPostParser, DirectPostJwtJweParser, detect_response_mode
from pyeudiw.openid4vp.exceptions import AuthRespParsingException, AuthRespValidationException, InvalidVPKeyBinding, InvalidVPToken, KIDNotFound
from pyeudiw.openid4vp.interface import VpTokenParser, VpTokenVerifier, AuthorizationResponseParser
from pyeudiw.openid4vp.schemas.flow import RemoteFlowType
from pyeudiw.openid4vp.schemas.response import ResponseMode
from pyeudiw.openid4vp.vp import Vp
from pyeudiw.openid4vp.vp_sd_jwt_vc import VpVcSdJwtParserVerifier
from pyeudiw.openid4vp.vp_sd_jwt import VpSdJwt
from pyeudiw.satosa.exceptions import (AuthorizeUnmatchedResponse, BadRequestError, FinalizedSessionError,
                                       InvalidInternalStateError, NotTrustedFederationError, HTTPError)
from pyeudiw.satosa.interfaces.response_handler import ResponseHandlerInterface
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.satosa.utils.trust import BackendTrust
from pyeudiw.sd_jwt.schema import VerifierChallenge
from pyeudiw.storage.exceptions import StorageWriteError
from pyeudiw.tools.utils import iat_now
from pyeudiw.tools.jwk_handling import find_vp_token_key
from pyeudiw.trust.exceptions import NoCriptographicMaterial


class ResponseHandler(ResponseHandlerInterface, BackendTrust):
    _SUPPORTED_RESPONSE_METHOD = "post"
    _SUPPORTED_RESPONSE_CONTENT_TYPE = "application/x-www-form-urlencoded"
    _ACCEPTED_ISSUER_METADATA_TYPE = "openid_credential_issuer"

    def _handle_credential_trust(self, context: Context, vp: Vp) -> bool:
        try:
            # establish the trust with the issuer of the credential by checking it to the revocation
            # inspect VP's iss or trust_chain if available or x5c if available
            # TODO: X.509 as alternative to Federation

            # for each single vp token, take the credential within it, use cnf.jwk to validate the vp token signature -> if not exception
            # establish the trust to each credential issuer
            tchelper = self._validate_trust(context, vp.payload['vp'])

            if not tchelper.is_trusted:
                return self._handle_400(context, f"Trust Evaluation failed for {tchelper.entity_id}")

            # TODO: generalyze also for x509
            if isinstance(vp, VpSdJwt):
                credential_jwks = tchelper.get_trusted_jwks(
                    metadata_type='openid_credential_issuer'
                )
                vp.set_credential_jwks(credential_jwks)
        except InvalidVPToken:
            return self._handle_400(context, f"Cannot validate VP: {vp.jwt}")
        except ValidationError as e:
            return self._handle_400(context, f"Error validating schemas: {e}")
        except KIDNotFound as e:
            return self._handle_400(context, f"Kid error: {e}")
        except NotTrustedFederationError as e:
            return self._handle_400(context, f"Not trusted federation error: {e}")
        except Exception as e:
            return self._handle_400(context, f"VP parsing error: {e}")

    def _extract_all_user_attributes(self, attributes_by_issuers: dict) -> dict:
        # for all the valid credentials, take the payload and the disclosure and disclose user attributes
        # returns the user attributes ...
        all_user_attributes = dict()
        for i in attributes_by_issuers.values():
            all_user_attributes.update(**i)
        return all_user_attributes

    def _parse_http_request(self, context: Context) -> dict:
        """Parse the http layer of the request to extract the dictionary data.

        :param context: the satosa context containing, among the others, the details of the HTTP request
        :type context: satosa.Context

        :return: a dictionary containing the request data
        :rtype: dict

        :raises BadRequestError: when request paramets are in a not processable state; the expected handling is returning 400
        """
        if (http_method := context.request_method.lower()) != ResponseHandler._SUPPORTED_RESPONSE_METHOD:
            raise BadRequestError(f"HTTP method [{http_method}] not supported")

        if (content_type := context.http_headers['HTTP_CONTENT_TYPE']) != ResponseHandler._SUPPORTED_RESPONSE_CONTENT_TYPE:
            raise BadRequestError(f"HTTP content type [{content_type}] not supported")

        _endpoint = f"{self.server_url}{context.request_uri}"
        if self.config["metadata"].get('response_uris_supported', None):
            if _endpoint not in self.config["metadata"]['response_uris_supported']:
                raise BadRequestError("response_uri not valid")

        return context.request

    def _retrieve_session_from_state(self, state: str) -> dict:
        """_retrieve_session_and_nonce_from_state tries to recover an
        authenticasion session by matching it with the state. Returns the whole
        session data (if found) and the nonce proposed in the authentication
        request that should be matched by the holder response.

        :returns: the authentication session information and the nonce challenge
            associated to that authentication request
        :rtype: tuple[dict, str]

        :raises AuthorizeUnmatchedResponse: if the state is not matched to any session
        :raises FinalizedSessionError: if the state is matched to an already closed session
        :raises InvalidInternalStateError: if the session contains invalid, corrupted or missing
            data of known reason.
        """
        request_session: dict = {}
        try:
            request_session = self.db_engine.get_by_state(state=state)
        except Exception as err:
            raise AuthorizeUnmatchedResponse(f"unable to find document-session associated to state {state}", err)

        if not request_session:
            raise InvalidInternalStateError(f"unable to find document-session associated to state {state}")

        if request_session.get("finalized", True):
            raise FinalizedSessionError(f"cannot accept response: session for state {state} corrupted or already finalized")

        nonce = request_session.get("nonce", None)
        if not nonce:
            raise InvalidInternalStateError(f"unable to find nonce in session associated to state {state}: corrupted data")
        return request_session

    def _is_same_device_flow(request_session: dict, context: Context) -> bool:
        initiating_session_id: str | None = request_session.get("session_id", None)
        if initiating_session_id is None:
            raise ValueError("invalid session storage information: missing [session_id]")
        current_session_id: str | None = context.state.get("SESSION_ID", None)
        if current_session_id is None:
            raise ValueError("missing session id in wallet authorization response")
        return initiating_session_id == current_session_id

    def response_endpoint(self, context: Context, *args: tuple) -> Redirect | JsonResponse:
        self._log_function_debug("response_endpoint", context, "args", args)

        # parse and eventually decrypt jwt in response
        try:
            authz_payload: AuthorizeResponsePayload = self._parse_authorization_response(context)
        except AuthRespParsingException as e400:
            self._handle_400(context, e400.args[0], e400.args[1])
        except AuthRespValidationException as e401:
            self._handle_401(context, "invalid authentication method: token might be invalid or expired", e401)
        self._log_debug(context, f"response URI endpoint response with payload {authz_payload}")

        request_session: dict = {}
        try:
            request_session = self._retrieve_session_from_state(authz_payload.state)
        except AuthorizeUnmatchedResponse as e400:
            return self._handle_400(context, e400.args[0], e400.args[1])
        except InvalidInternalStateError as e500:
            return self._handle_500(context, e500.args[0], "invalid state")
        except FinalizedSessionError as e400:
            return self._handle_400(context, e400.args[0], HTTPError(e400.args[0]))

        # the flow below is a simplified algorithm of authentication response processing, where:
        # (1) we don't check that presentation submission matches definition (yet)
        # (2) we don't check that vp tokens are aligned with information declared in the presentation submission
        # (3) we use all disclosed claims in vp tokens to build the user identity
        attributes_by_issuer: dict[str, dict[str, Any]] = {}
        credential_issuers: list[str] = []
        encoded_vps: list[str] = [authz_payload.vp_token] if isinstance(authz_payload.vp_token, str) else authz_payload.vp_token

        for vp_token in encoded_vps:
            # verify vp token and extract user information
            try:
                token_parser, token_verifier = self._vp_verifier_factory(authz_payload.presentation_submission, vp_token, request_session)
            except ValueError as e:
                return self._handle_400(context, f"VP parsing error: {e}")
            
            try:
                pub_jwk = find_vp_token_key(token_parser, self.trust_evaluator)
            except NoCriptographicMaterial as e:
                return self._handle_400(context, f"VP parsing error: {e}")
            token_issuer = token_parser.get_issuer_name()
            whitelisted_keys = self.trust_evaluator.get_public_keys(token_issuer)
            try:
                token_verifier.verify_signature(whitelisted_keys)
            except Exception as e:
                return self._handle_400(context, f"VP parsing error: {e}")
            
            try:
                token_verifier.verify_challenge()
            except InvalidVPKeyBinding as e:
                return self._handle_400(context, f"VP parsing error: {e}")
            
            claims = token_parser.get_credentials()
            iss = token_parser.get_issuer_name()
            attributes_by_issuer[iss] = claims
            self._log_debug(context, f"disclosed claims {claims} from issuer {iss}")
          
        all_attributes = self._extract_all_user_attributes(attributes_by_issuer)
        iss_list_serialized = ";".join(credential_issuers)  # marshaling is whatever
        internal_resp = self._translate_response(all_attributes, iss_list_serialized, context)

        state = authz_payload.state
        response_code = self.response_code_helper.create_code(state)
        try:
            self.db_engine.update_response_object(
                request_session['nonce'], state, internal_resp
            )
            # authentication finalized!
            self.db_engine.set_finalized(request_session['document_id'])
            if self.effective_log_level == logging.DEBUG:
                request_session = self.db_engine.get_by_state(state=state)
                self._log_debug(
                    context, f"Session update on storage: {request_session}")

        except StorageWriteError as e:
            # TODO - do we have to block in the case the update cannot be done?
            self._log_error(context, f"Session update on storage failed: {e}")
            return self._handle_500(context, "Cannot update response object.", e)

        try:
            flow_type = RemoteFlowType(request_session["remote_flow_typ"])
        except ValueError as e:
            self._log_error(context, f"unable to identify flow from stored session: {e}")
            return self._handle_500(context, "error in authentication response processing", e)

        match flow_type:
            case RemoteFlowType.SAME_DEVICE:
                cb_redirect_uri = f"{self.registered_get_response_endpoint}?response_code={response_code}"
                return JsonResponse({"redirect_uri": cb_redirect_uri}, status="200")                
            case RemoteFlowType.CROSS_DEVICE:
                return JsonResponse({"status": "OK"}, status="200")    
            case unsupported:
                _msg = f"unrecognized remote flow type: {unsupported}"
                self._log_error(context, _msg)
                return self._handle_500(context, "error in authentication response processing", Exception(_msg))

    def _translate_response(self, response: dict, issuer: str, context: Context) -> InternalData:
        """
        Translates wallet response to SATOSA internal response.
        :type response: dict[str, str]
        :type issuer: str
        :type subject_type: str
        :rtype: InternalData
        :param response: Dictioary with attribute name as key.
        :param issuer: The oidc op that gave the repsonse.
        :param subject_type: public or pairwise according to oidc standard.
        :return: A SATOSA internal response.
        """
        # it may depends by credential type and attested security context evaluated
        # if WIA was previously submitted by the Wallet
        timestamp_epoch = (
            response.get("auth_time")
            or response.get("iat")
            or iat_now()
        )
        timestamp_dt = datetime.datetime.fromtimestamp(
            timestamp_epoch,
            datetime.timezone.utc
        )
        timestamp_iso = timestamp_dt.isoformat().replace("+00:00", "Z")

        auth_class_ref = (
            response.get("acr") or
            response.get("amr") or
            self.config["authorization"]["default_acr_value"]
        )
        auth_info = AuthenticationInformation(
            auth_class_ref, timestamp_iso, issuer)

        # TODO - ACR values
        internal_resp = InternalData(auth_info=auth_info)

        # (re)define the response subject
        sub = ""
        pepper = self.config.get("user_attributes", {})[
            'subject_id_random_value'
        ]
        for i in self.config.get("user_attributes", {}).get("unique_identifiers", []):
            if response.get(i):
                _sub = response[i]
                sub = hashlib.sha256(
                    f"{_sub}~{pepper}".encode(
                    )
                ).hexdigest()
                break

        if not sub:
            self._log(
                context,
                level='warning',
                message=(
                    "[USER ATTRIBUTES] Missing subject id from OpenID4VP presentation "
                    "setting a random one for interop for internal frontends"
                )
            )
            sub = hashlib.sha256(
                f"{json.dumps(response).encode()}~{pepper}".encode()
            ).hexdigest()
        response["sub"] = [sub]

        internal_resp.attributes = self.converter.to_internal(
            "openid4vp", response
        )
        internal_resp.subject_id = sub
        return internal_resp

    def _parse_authorization_response(self, context: Context) -> AuthorizeResponsePayload:
        response_mode = detect_response_mode(context)
        match response_mode:
            case ResponseMode.direct_post:
                parser = DirectPostParser()
                return parser.parse_and_validate(context)
            case ResponseMode.direct_post_jwt:
                parser = DirectPostJwtJweParser(self.config["metadata_jwks"])
                return parser.parse_and_validate(context)
            case _:
                raise AuthRespParsingException(
                    f"invalid or unrecognized response mode: {response_mode}",
                    Exception("invalid program state")
                )

    def _vp_verifier_factory(self, presentation_submission: dict, token: str, session_data: dict) -> tuple[VpTokenParser, VpTokenVerifier]:
        # TODO: la funzione dovrebbe consumare la presentation submission per sapere quale token
        # ritornare - per ora viene ritornata l'unica implementazione possibile
        challenge = self._get_verifier_challenge(session_data)
        token_processor = VpVcSdJwtParserVerifier(token, challenge["aud"], challenge["nonce"])
        return (token_processor, deepcopy(token_processor))

    def _get_verifier_challenge(self, session_data: dict) -> VerifierChallenge:
        return {"aud": self.client_id, "nonce": session_data["nonce"]}