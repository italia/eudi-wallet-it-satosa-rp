import os
from pydantic import ValidationError
import yaml
import importlib
from typing import Dict, Any
import logging

from pyeudiw.openid4vp.presentation_submission.schemas import PresentationSubmissionSchema

logger = logging.getLogger(__name__)

class PresentationSubmission:
    def __init__(self, submission: Dict[str, Any]):
        """
        Initialize the PresentationSubmission handler with the submission data.

        Args:
            submission (Dict[str, Any]): The presentation submission data.

        Raises:
            KeyError: If the 'format' key is missing in the submission.
            ValueError: If the format is not supported or not defined in the configuration.
            ImportError: If the module or class cannot be loaded.
            ValidationError: If the submission data is invalid or exceeds size limits.
        """
        self.config = self._load_config()
        self.submission = self._validate_submission(submission)
        self.handlers = self._initialize_handlers()

    def _load_config(self) -> Dict[str, Any]:
        """
        Load the configuration from format_config.yml located in the same directory.

        Returns:
            Dict[str, Any]: The configuration dictionary.

        Raises:
            FileNotFoundError: If the configuration file is not found.
        """
        config_path = os.path.join(os.path.dirname(__file__), "config.yml")
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_path, "r") as config_file:
            return yaml.safe_load(config_file)
        
    def _validate_submission(self, submission: Dict[str, Any]) -> PresentationSubmissionSchema:
        """
        Validate the submission data using Pydantic and check its total size.

        Args:
            submission (Dict[str, Any]): The presentation submission data.

        Returns:
            PresentationSubmissionSchema: Validated submission schema.

        Raises:
            ValidationError: If the submission data is invalid or exceeds size limits.
        """
        max_size = self.config.get("MAX_SUBMISSION_SIZE", 10 * 1024 * 1024)

        # Check submission size
        submission_size = len(str(submission).encode("utf-8"))
        if submission_size > max_size:
            logger.warning(
                f"Rejected submission: size {submission_size} bytes exceeds limit {max_size} bytes."
            )
            raise ValueError(
                f"Submission size exceeds maximum allowed limit of {max_size} bytes."
            )

        try:
            return PresentationSubmissionSchema(**submission)
        except ValidationError as e:
            logger.error(f"Submission validation failed: {e}")
            raise

    def _initialize_handlers(self) -> Dict[int, object]:
        """
        Initialize handlers for each item in the 'descriptor_map' of the submission.

        Returns:
            Dict[int, object]: A dictionary mapping indices to handler instances.

        Raises:
            KeyError: If the 'format' key is missing in any descriptor.
            ValueError: If a format is not supported or not defined in the configuration.
            ImportError: If a module or class cannot be loaded.
        """
        handlers = {}

        try:
            descriptor_map = self.submission.descriptor_map
        except KeyError:
            raise KeyError("The 'descriptor_map' key is missing in the submission.")

        for index, descriptor in enumerate(descriptor_map):
            format_name = descriptor.format
            if not format_name:
                raise KeyError(f"The 'format' key is missing in descriptor at index {index}.")

            # Search for the format in the configuration
            format_conf = next((fmt for fmt in self.config.get("formats", []) if fmt["name"] == format_name), None)
            if not format_conf:
                raise ValueError(f"Format '{format_name}' is not supported or not defined in the configuration.")

            module_name = format_conf["module"]
            class_name = format_conf["class"]

            try:
                # Dynamically load the module and class
                module = importlib.import_module(module_name)
                cls = getattr(module, class_name)
                handlers[index] = cls()  # Instantiate the class
            except ModuleNotFoundError:
                logger.warning(f"Module '{module_name}' not found for format '{format_name}'. Skipping index {index}.")
            except AttributeError:
                logger.warning(f"Class '{class_name}' not found in module '{module_name}' for format '{format_name}'. Skipping index {index}.")
            except Exception as e:
                logger.warning(f"Error loading format '{format_name}' for index {index}: {e}")

        return handlers
