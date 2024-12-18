import pytest
from unittest.mock import patch, MagicMock
from pydantic import ValidationError
from pyeudiw.openid4vp.presentation_submission.presentation_submission import PresentationSubmission


# Mock data for testing
mock_format_config = {
    "formats": [
        {"name": "ldp_vp", "module": "mock.module", "class": "MockLdpVpHandler"},
        {"name": "jwt_vp_json", "module": "mock.module", "class": "MockJwtVpJsonHandler"}
    ],
    "MAX_SUBMISSION_SIZE": 10 * 1024  # 10 KB
}

valid_submission = {
    "id": "submission_id",
    "definition_id": "definition_id",
    "descriptor_map": [
        {"id": "descriptor_1", "format": "ldp_vp", "path": "$"},
        {"id": "descriptor_2", "format": "jwt_vp_json", "path": "$"}
    ]
}

large_submission = {
    "id": "submission_id_large",
    "definition_id": "definition_id_large",
    "descriptor_map": [{"id": f"descriptor_{i}", "format": "ldp_vp", "path": "$"} for i in range(101)]  # Exceeds limit
}


def test_presentation_submission_initialization_with_schema_validation():
    """
    Test that the PresentationSubmission class initializes correctly
    and validates against the Pydantic schema.
    """
    # Mock handler classes
    mock_ldp_vp_handler = MagicMock(name="MockLdpVpHandler")
    mock_jwt_vp_json_handler = MagicMock(name="MockJwtVpJsonHandler")

    # Mock import_module to return a fake module with our mock classes
    mock_module = MagicMock()
    setattr(mock_module, "MockLdpVpHandler", mock_ldp_vp_handler)
    setattr(mock_module, "MockJwtVpJsonHandler", mock_jwt_vp_json_handler)

    with patch("pyeudiw.openid4vp.presentation_submission.presentation_submission.PresentationSubmission._load_config", return_value=mock_format_config), \
         patch("importlib.import_module", return_value=mock_module):
        
        # Initialize the class
        ps = PresentationSubmission(valid_submission)

        # Assert that handlers were created for all formats in descriptor_map
        assert len(ps.handlers) == len(valid_submission["descriptor_map"]), "Not all handlers were created."

        # Check that the handlers are instances of the mocked classes
        assert ps.handlers[0] is mock_ldp_vp_handler(), "Handler for 'ldp_vp' format is incorrect."
        assert ps.handlers[1] is mock_jwt_vp_json_handler(), "Handler for 'jwt_vp_json' format is incorrect."


def test_presentation_submission_large_submission_with_schema():
    """
    Test that the PresentationSubmission class raises a ValidationError
    when the submission exceeds the descriptor_map size limit.
    """
    with patch("pyeudiw.openid4vp.presentation_submission.presentation_submission.PresentationSubmission._load_config", return_value=mock_format_config):
        # Expect a ValidationError for exceeding descriptor_map size limit
        with pytest.raises(ValidationError, match="descriptor_map exceeds maximum allowed size of 100 items"):
            PresentationSubmission(large_submission)


def test_presentation_submission_missing_descriptor_key():
    """
    Test that the PresentationSubmission class raises a ValidationError
    when required keys are missing in the descriptor_map.
    """
    invalid_submission = {
        "id": "invalid_submission_id",
        "definition_id": "invalid_definition_id",
        "descriptor_map": [
            {"format": "ldp_vp"}
        ]
    }

    with patch("pyeudiw.openid4vp.presentation_submission.presentation_submission.PresentationSubmission._load_config", return_value=mock_format_config):

        with pytest.raises(ValidationError, match=r"Field required"):
            PresentationSubmission(invalid_submission)

def test_presentation_submission_invalid_format():
    """
    Test that the PresentationSubmission class raises a ValueError
    when an unsupported format is encountered.
    """
    invalid_submission = {
        "id": "invalid_submission_id",
        "definition_id": "invalid_definition_id",
        "descriptor_map": [
            {"format": "unsupported_format", "id": "descriptor_1", "path": "$"}
        ]
    }

    with patch("pyeudiw.openid4vp.presentation_submission.presentation_submission.PresentationSubmission._load_config", return_value=mock_format_config):
        with pytest.raises(ValueError, match="Format 'unsupported_format' is not supported or not defined in the configuration."):
            PresentationSubmission(invalid_submission)

def test_presentation_submission_missing_format_key():
    """
    Test that the PresentationSubmission class raises a KeyError
    when the 'format' key is missing in a descriptor.
    """
    missing_format_key_submission = {
        "id": "missing_format_submission_id",
        "definition_id": "missing_format_definition_id",
        "descriptor_map": [
            {"id": "descriptor_1", "path": "$"}  # Missing 'format' key
        ]
    }

    with patch("pyeudiw.openid4vp.presentation_submission.presentation_submission.PresentationSubmission._load_config", return_value=mock_format_config):
         with pytest.raises(ValidationError, match=r"descriptor_map\.0\.format\s+Field required"):
            PresentationSubmission(missing_format_key_submission)
