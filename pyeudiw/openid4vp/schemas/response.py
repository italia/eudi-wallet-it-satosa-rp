from dataclasses import dataclass
from enum import Enum
from typing import Optional

from pydantic import BaseModel, field_validator

from pyeudiw.jwt.utils import is_jwe_format, is_jwt_format


class DescriptorSchema(BaseModel):
    id: str
    path: str
    format: str


class PresentationSubmissionSchema(BaseModel):
    definition_id: str
    id: str
    descriptor_map: list[DescriptorSchema]


class ResponseMode(str, Enum):
    direct_post = "direct_post"
    direct_post_jwt = "direct_post.jwt"


class ResponseSchema(BaseModel):
    state: Optional[str]
    nonce: str
    vp_token: str
    presentation_submission: PresentationSubmissionSchema

    @field_validator("vp_token")
    @classmethod
    def _check_vp_token(cls, vp_token):
        if is_jwt_format(vp_token):
            return vp_token
        else:
            raise ValueError("vp_token is not in a JWT format.")

@dataclass
class AuthorizeResponseDirectPostJwt:
    response: str  # jwt

    def __post_init__(self):
        jwt = self.response
        if not is_jwe_format(jwt) and not is_jwt_format(jwt):
            raise ValueError(f"input response={jwt} is neither jwt not jwe format")


@dataclass
class AuthorizeResponsePayload:
    """
    AuthorizeResponsePayload is a simple schema class for
        https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-parameters
    only for the case when presentation submission is used over DCQL.

    This class is a weaker validation than pyeudiw.openid4vp.schema.ResponseSchema
    as it is not meant to validate the _content_ of the response; just that the
    representation lands with the proper expected claims
    """
    state: str
    vp_token: str | list[str]
    presentation_submission: dict
