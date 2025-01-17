import pytest
import satosa.context

from pyeudiw.jwt.jwe_helper import JWEHelper
from pyeudiw.openid4vp.authorization_response import DirectPostJwtJweParser, DirectPostParser
from pyeudiw.openid4vp.exceptions import AuthRespParsingException, AuthRespValidationException


@pytest.fixture
def jwe_helper():
    private_key = {
        "kid": "DwR3tX_BuSwRrn3HjXom_ajjMGzu_15r_mJeG0HBilo",
        "d": "UgwHyOMdyfF2dK6EjF6LX6Tyu0Ylha9SaaFgOBhjjRi1XW3FLy83iPRxCRHSHC-d3DMCZaK7wa0qDmok8KaVOhmL0V_LKcNaDaJHDxAynlWdnh8IJnlDOGuALeDAPiC5vCvVVkRcAo4F8KbOvaxkMZLPVqwlM5lYC31yD6aXPb3f6raNy-Jl9t1Jt_OYH9LobqgllZwu9S5qkXzBqfjCw4ymcu7VTi_P3dt141cja2eSZjG5bPORZ6Wy3gd9dQkLfdpjJXo5nSA1UC8cNpOLf8NZU659enPQ6nItyrt2Kx5aNwizD993TjrVuNloKUSI5DlNznh3JdDy_nWt7GyQr-tp_9l2Xma5heSix9Az8w1_0J3xUo4wK3hfe5-WD3HkYjeJyp9CqMNNKGR8LXz7KX_lUN2-U2hiodKKnf0y6NK9zhakgoox4kSfmOUTt0ir_4wWGqoAIh6QF1yfXkVsdJ7LyMTdu2B54Kv4M41g98ifP2UjKicreCW3Lw--KmJJ",
        "e": "AQAB",
        "kty": "RSA",
        "n": "vxPbeX_PgRI5mpOoANQkC1HU09LZePPygjaUtrXrZkx0rhK-2LaoNLns5EoBkJOuj8JrHU_W2UOZBIE-tpLJ8UUSuJNXNZhrWqezhjO0aIue_JgyMWjp2IZ_BofyhrMenqYI6oA8B9eKdD-1zxF0vflCHylq7vdYcKKPZcr0QjyVTltuEbRiS8WHjFV5_sWuYJkDt-5bXW4ZapDV4NG2OcwcRROR5gwU1EhWX-kQbNPw84wZpEGXy5fFTaosfUVbvKSXP_d8IZ4fizqMi69bk6IjLqfw3JZcIKnzz7ou302dq2sIH_R1gQHNJ6b-oTh5nq3JLCMViGHZAH0sIMu6eiLzvcADX5PpbMO9Y83l-UbMEqH0iv7wtW3gVE7OjolZCiFXwhhntWj5ccomlzgYFreebRevQItHZUxiN7n7tJMOWouV1LHecWfixHbweaBFooGSzY9hlFvERKmbfPqNaIce8PHd-dDWw9Yxq5RdNpcMQKm5ruYlV3pWGxoQaHdX",
        "p": "zxOeQgvnCZzIIsZoz18ROo8fCRZT7K6h4uvz6fvTz6e_6TKWUYohjsBfYAkbNgJamkxdSJyaQWDMPs0mIG2j2IcpqG0JJGQ68QCqai8H-o-_wb0hjp3fY6TofVaEzFvQiOJE2ZyqtSn7hDrEFEmceJB_VzIvOZbS-AZo9--R2PTQ4h7CurkWKCOKAbeBfOWEX_s6UOaLQzMYDykiHSlPQmF9BZAsaoRHXdZLlsgxgQ3nbPbsBx2d1axlIIhb7Xkl",
        "q": "7DiV8cgKFnOGCTHT3cr_8xIKwD0LoWnGibqdA2p0XSQTXTLUr532DKK_3YMdm0F0YtCyPQBbsJoLspbnK6yTo3RPFr0zooJ5eCYnLO_qOBYFwYbOhhXrYPjfpEDSXls9BD6cHhCCQtiNAADIjaMpmoEexPD6lMoijTF7qzEst2fszvYTToczroWHPe8RuJR7J_FEM-soD99ERqJanj5BUs-ruuNwshM_Fp7C-ubt9PbMo9gv5p9nrsT8oAI7wJvL",
        "use": "enc"
    }
    jwe_helper = JWEHelper(private_key)
    return jwe_helper


def test_direct_post_parser_good_case():
    parser = DirectPostParser()

    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {
                "id": "verifiable-credential-type",
                "format": "dc+sd-jwt",
                "path": "$.vct"
            }
        ]
    }
    ctx.request = {
        "vp_token": vp_token,
        "state": state,
        "presentation_submission": presentation_submission
    }

    resp = parser.parse_and_validate(ctx)
    assert resp.vp_token == vp_token
    assert resp.state == state
    assert resp.presentation_submission == presentation_submission


def test_direct_post_response_bad_parse_case():
    # case 0: bad method
    parser = DirectPostParser()

    ctx = satosa.context.Context()
    ctx.request_method = "GET"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {
                "id": "verifiable-credential-type",
                "format": "dc+sd-jwt",
                "path": "$.vct"
            }
        ]
    }
    ctx.qs_params = {
        "vp_token": vp_token,
        "state": state,
        "presentation_submission": presentation_submission
    }

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted a GET request when only POST can be accepted"
    except AuthRespParsingException:
        assert True
    except AuthRespValidationException as e:
        assert False, f"obtained unexpected validation exception: {e}"

    # case 1: bad shape
    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    ctx.request = {
        "bad_param_name": "bad parameter value",
    }

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted an direct post with invalid parameters"
    except AuthRespParsingException:
        assert True
    except AuthRespValidationException as e:
        assert False, f"obtained unexpected validation exception: {e}"


def test_direct_post_jwt_jwe_parser_good_case(jwe_helper):

    parser = DirectPostJwtJweParser(jwe_helper)

    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {
                "id": "verifiable-credential-type",
                "format": "dc+sd-jwt",
                "path": "$.vct"
            }
        ]
    }
    data = {
        "vp_token": vp_token,
        "state": state,
        "presentation_submission": presentation_submission
    }
    ctx.request = {
        "response": jwe_helper.encrypt(data)
    }

    resp = parser.parse_and_validate(ctx)
    assert resp.vp_token == vp_token
    assert resp.state == state
    assert resp.presentation_submission == presentation_submission


def test_direct_post_jwt_jwe_parser_bad_parse_case(jwe_helper):
    # case 0: bad method
    parser = DirectPostJwtJweParser(jwe_helper)

    ctx = satosa.context.Context()
    ctx.request_method = "GET"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {
                "id": "verifiable-credential-type",
                "format": "dc+sd-jwt",
                "path": "$.vct"
            }
        ]
    }
    ctx.qs_params = {
        "response": jwe_helper.encrypt({
            "vp_token": vp_token,
            "state": state,
            "presentation_submission": presentation_submission
        })
    }

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted a GET request when only POST can be accepted"
    except AuthRespParsingException:
        assert True
    except AuthRespValidationException as e:
        assert False, f"obtained unexpected validation exception: {e}"

    # case 1: bad shape
    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    ctx.request = {
        "response": jwe_helper.encrypt({"bad_param_name": "bad parameter value"}),
    }

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted an direct post with invalid parameters"
    except AuthRespParsingException:
        assert True
    except AuthRespValidationException as e:
        assert False, f"obtained unexpected validation exception: {e}"


def test_direct_post_jwt_jwe_parser_bad_validation_case(jwe_helper):
    parser = DirectPostJwtJweParser(jwe_helper)

    wrong_public_key = {
        "kid": "ybmSufrnl3Cu6OrNcsOF_g95g5zShf2aKpg59PMcMm8",
        "e": "AQAB",
        "kty": "RSA",
        "n": "sCLDmvDKr4y7EHLf4TbjNqa3_p4GnTLqPXdvi0ce2BW2NIK1vYtz9uk8oIlResIWJk1T59LAS8YGF5BLkjLLSyMjrhHySoyRDrBEk_cz-F3Mabc7x-5GDAbxvFDZKQ2n5UVQUWgboFISGp2zpmrYzvewv2WCxZ4a3mS6kwAvjl_S9kahD-SFjiNyHsSaA0lDrF5xQpT2MaMha0dPwgNrChCcG4TTG5YBy4zgktlfA9GRnrEKUJioiKYapMAotziNRBoH128CJGAdMxaO5SVYC0PVLnmKd3cv4bPqGYMRszI6x3i5YUTLk8HwWPL9SUV25pAFp_nDRlgQTdvxssClhZ8VbMZQ3x2I738ixGud_1ggBVFTGDDGDQem4jOz6AsPBVrwtwWStVpA5V5FyEhbgZmE7Orb0cNsmIBjVIPBuFtLBmSELAiJ_WK7ajo3xKtIMTFB-JVX1PVawZOkUzS94BnJ0i7RGc4uzZBhhiOWxBHQGIFhfJnD1OggXnHkVYRn",
        "use": "enc"
    }
    wrong_helper = JWEHelper(wrong_public_key)

    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {
                "id": "verifiable-credential-type",
                "format": "dc+sd-jwt",
                "path": "$.vct"
            }
        ]
    }
    data = {
        "vp_token": vp_token,
        "state": state,
        "presentation_submission": presentation_submission
    }
    ctx.request = {
        "response": wrong_helper.encrypt(data)
    }

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted an direct post with wrong encryption"
    except AuthRespParsingException as e:
        assert False, f"obtained unexpected parsing exception: {e}"
    except AuthRespValidationException:
        assert True
