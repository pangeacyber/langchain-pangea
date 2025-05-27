from __future__ import annotations

import os
from typing import TYPE_CHECKING

from pangea.services import Redact
from pydantic import SecretStr

from langchain_pangea.tools.base import PangeaBaseTool

if TYPE_CHECKING:
    from pangea import PangeaConfig


class PangeaRedactGuardError(RuntimeError):
    """
    Exception raised for unexpected scenarios.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)


class PangeaRedactGuard(PangeaBaseTool):
    """
    Redact sensitive and high-risk information from prompts, responses, and RAG context data using the Pangea Redact service.
    Details of the service can be found here:
        [Redact API Reference docs](https://pangea.cloud/docs/api/redact)
    Requirements:
        - Environment variable ``PANGEA_REDACT_TOKEN`` must be set,
          or passed as a named parameter to the constructor.
    How to use:
        .. code-block:: python
            import os
            from langchain_community.tools.pangea.redact_guard import PangeaRedactGuard, PangeaConfig
            from pydantic import SecretStr
            # Initialize parameters
            token = SecretStr(os.getenv("PANGEA_REDACT_TOKEN"))
            config = PangeaConfig(domain="aws.us.pangea.cloud")
            # Setup Pangea Redact Tool Guard
            redact_guard = PangeaRedactGuard(token=token, config_id="", config=config)
            # Run as a tool for agents
            redact_guard.run("My name is Dennis Nedry and my email is you.didnt.say.the.magic.word@gmail.com")
            # Run as a Runnable for chains
            redact_guard.invoke("My name is Dennis Nedry and my email is you.didnt.say.the.magic.word@gmail.com")
    """  # noqa: E501

    def __init__(
        self,
        *,
        token: SecretStr | None = None,
        config: PangeaConfig | None = None,
        config_id: str | None = None,
        token_env_key_name: str = "PANGEA_REDACT_TOKEN",
    ) -> None:
        """
        Args:
            token: Pangea Redact API token.
            config_id: Pangea Redact configuration ID.
            config: PangeaConfig object.
        """

        if not token:
            token = SecretStr(os.getenv(token_env_key_name, ""))

        if not token or not token.get_secret_value() or token.get_secret_value() == "":
            raise ValueError(f"'{token_env_key_name}' must be set or passed")

        super().__init__(
            name="pangea-redact-guard-tool",
            description=(
                "Redacts sensitive and high-risk information from prompts, responses, "
                "and RAG context data using the Pangea Redact service."
            ),
        )

        self._redact_client = Redact(token=token.get_secret_value(), config=config, config_id=config_id)

    def _process_text(self, input_text: str) -> str:
        # Redact the input_text
        redacted = self._redact_client.redact(text=input_text)

        if not redacted.result:
            raise PangeaRedactGuardError("Result is invalid or missing")

        # Return the redacted text or the input_text if no redacted text is found
        return redacted.result.redacted_text or input_text
