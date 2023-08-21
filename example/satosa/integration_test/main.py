import requests
import os
import uuid
import urllib
import datetime
import jwcrypto

from pyeudiw.jwt import DEFAULT_SIG_KTY_MAP
from pyeudiw.tests.federation.base import (
    EXP,
    leaf_cred,
    leaf_cred_jwk,
    leaf_wallet_jwk,
    trust_chain_issuer,
    trust_chain_wallet,
    ta_ec
)

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper, JWEHelper
from pyeudiw.oauth2.dpop import DPoPIssuer, DPoPVerifier
from pyeudiw.sd_jwt import (
    load_specification_from_yaml_string,
    issue_sd_jwt,
    _adapt_keys,
    import_pyca_pri_rsa
)
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.jwt.utils import unpad_jwt_payload
from pyeudiw.tools.utils import iat_now, exp_from_now

from saml2_sp import saml2_request, IDP_BASEURL
from sd_jwt.holder import SDJWTHolder


CONFIG_DB = {
  "mongo_db": {
    "storage": {
      "module": "pyeudiw.storage.mongo_storage",
      "class": "MongoStorage",
      "init_params": {
        "url": "mongodb://localhost:27017/",
        "conf": {
          "db_name": "eudiw",
          "db_sessions_collection": "sessions",
          "db_trust_attestations_collection": "trust_attestations",
          "db_trust_anchors_collection": "trust_anchors"
        },
        "connection_params": {}
      }
    }
  }
}


WALLET_INSTANCE_ATTESTATION = {
    "iss": "https://wallet-provider.example.org",
    "sub": "vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
    "type": "WalletInstanceAttestation",
    "policy_uri": "https://wallet-provider.example.org/privacy_policy",
    "tos_uri": "https://wallet-provider.example.org/info_policy",
    "logo_uri": "https://wallet-provider.example.org/logo.svg",
    "asc": "https://wallet-provider.example.org/LoA/basic",
    "cnf":
    {
        "jwk": leaf_wallet_jwk.serialize()
    },
    "authorization_endpoint": "eudiw:",
    "response_types_supported": [
        "vp_token"
    ],
    "vp_formats_supported": {
        "jwt_vp_json": {
            "alg_values_supported": ["ES256"]
        },
        "jwt_vc_json": {
            "alg_values_supported": ["ES256"]
        }
    },
    "request_object_signing_alg_values_supported": [
        "ES256"
    ],
    "presentation_definition_uri_supported": False,
    "iat": iat_now(),
    "exp": exp_from_now()
}

req_url = f"{saml2_request['headers'][0][1]}&idp_hinting=wallet"
headers_mobile = {
    'User-Agent' : 'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B137 Safari/601.1'
}

request_uri = ''

# initialize the user-agent
http_user_agent = requests.Session()

try:
    authn_response = http_user_agent.get(
        url = req_url, 
        verify=False, 
        headers=headers_mobile
    )
except requests.exceptions.InvalidSchema as e:
    request_uri = urllib.parse.unquote_plus(e.args[0].split("request_uri=")[1][:-1]
)

# STORAGE ####
# Put the trust anchor EC and the trust chains related to the credential issuer and the wallet provider in the trust storage
db_engine_inst = DBEngine(CONFIG_DB)
db_engine_inst.add_trust_anchor(
    ta_ec['iss'], 
    ta_ec, 
    datetime.datetime.now().isoformat()
)

WALLET_PRIVATE_JWK = JWK(leaf_wallet_jwk.serialize(private=True))
WALLET_PUBLIC_JWK = JWK(leaf_wallet_jwk.serialize())
# PRIVATE_JWK = leaf_wallet_jwk.serialize(private=True)
jwshelper = JWSHelper(WALLET_PRIVATE_JWK)
dpop_wia = jwshelper.sign(
    WALLET_INSTANCE_ATTESTATION,
    protected={
        'trust_chain': trust_chain_wallet,
        'typ': "va+jwt"
    }
)

dpop_proof = DPoPIssuer(
        htu=request_uri,
        token=dpop_wia,
        private_jwk=WALLET_PRIVATE_JWK
).proof
dpop_test = DPoPVerifier(
    public_jwk=leaf_wallet_jwk.serialize(),
    http_header_authz=f"DPoP {dpop_wia}",
    http_header_dpop=dpop_proof
)
print(f"dpop is valid: {dpop_test.is_valid}")

http_headers = {
    "AUTHORIZATION":f"DPoP {dpop_wia}",
    "DPOP":dpop_proof
}

sign_request_obj = http_user_agent.get(request_uri, verify=False, headers=http_headers)
print(sign_request_obj.json())

redirect_uri = unpad_jwt_payload(sign_request_obj.json()['response'])['response_uri']

# create a SD-JWT signed by a trusted credential issuer
issuer_jwk = leaf_cred_jwk
ISSUER_CONF = {
    "sd_specification": """
        user_claims:
            !sd unique_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            !sd given_name: "Mario"
            !sd family_name: "Rossi"
            !sd birthdate: "1980-01-10"
            !sd place_of_birth:
                country: "IT"
                locality: "Rome"
            !sd tax_id_code: "TINIT-XXXXXXXXXXXXXXXX"

        holder_disclosed_claims:
            { "given_name": "Mario", "family_name": "Rossi", "place_of_birth": {country: "IT", locality: "Rome"}, "tax_id_code": "TINIT-XXXXXXXXXXXXXXXX" }

        key_binding: True
    """,
    "issuer": leaf_cred['sub'],
    "default_exp": 1024
}
settings = ISSUER_CONF
settings['issuer'] = "https://credential_issuer.example.com"
settings['default_exp'] = 33

sd_specification = load_specification_from_yaml_string(
    settings["sd_specification"]
)

ISSUER_PRIVATE_JWK = JWK(leaf_cred_jwk.serialize(private=True))

issued_jwt = issue_sd_jwt(
    sd_specification,
    settings,
    ISSUER_PRIVATE_JWK,
    WALLET_PUBLIC_JWK,
    trust_chain = trust_chain_issuer
)

adapted_keys = _adapt_keys(
    issuer_key = ISSUER_PRIVATE_JWK,
    holder_key = WALLET_PUBLIC_JWK,
)

sdjwt_at_holder = SDJWTHolder(
    issued_jwt["issuance"],
    serialization_format="compact",
)
sdjwt_at_holder.create_presentation(
    claims_to_disclose = {
        'tax_id_code': "TIN-that",
        'given_name': 'Raffaello',
        'family_name': 'Mascetti'
    }, 
    nonce = str(uuid.uuid4()), 
    aud = str(uuid.uuid4()), 
    sign_alg = DEFAULT_SIG_KTY_MAP[WALLET_PRIVATE_JWK.key.kty],
    holder_key = (
        import_pyca_pri_rsa(WALLET_PRIVATE_JWK.key.priv_key, kid=WALLET_PRIVATE_JWK.kid) 
        if sd_specification.get("key_binding", False) 
        else None
    )
)

red_data = unpad_jwt_payload(sign_request_obj.json()['response'])
req_nonce = red_data['nonce']

data = {
    "iss": "https://wallet-provider.example.org/instance/vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
    "jti": str(uuid.uuid4()),
    "aud": "https://relying-party.example.org/callback",
    "iat": iat_now(),
    "exp": exp_from_now(minutes=5),
    "nonce": req_nonce,
    "vp": sdjwt_at_holder.sd_jwt_presentation,
}

vp_token = JWSHelper(WALLET_PRIVATE_JWK).sign(
    data,
    protected={"typ": "JWT"}
)

# take relevant information from RP's EC
rp_ec_jwt = http_user_agent.get(
    f'{IDP_BASEURL}/OpenID4VP/.well-known/openid-federation', 
    verify=False
).content.decode()
rp_ec = unpad_jwt_payload(rp_ec_jwt)

assert redirect_uri == rp_ec["metadata"]['wallet_relying_party']["redirect_uris"][0]

response = {
    "state": red_data['state'],
    "vp_token": vp_token,
    "presentation_submission": {
        "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "id": "04a98be3-7fb0-4cf5-af9a-31579c8b0e7d",
        "descriptor_map": [
            {
                "id": "pid-sd-jwt:unique_id+given_name+family_name",
                "path": "$.vp_token.verified_claims.claims._sd[0]",
                "format": "vc+sd-jwt"
            }
        ],
    "aud": redirect_uri
    }
}
encrypted_response = JWEHelper(
    JWK(rp_ec["metadata"]['wallet_relying_party']['jwks'][1]) # RSA (EC is not fully supported todate)
).encrypt(response)


sign_request_obj = http_user_agent.post(
    redirect_uri, 
    verify=False, 
    data={'response': encrypted_response}
)

assert 'SAMLResponse' in sign_request_obj.content.decode()
print(sign_request_obj.content.decode())