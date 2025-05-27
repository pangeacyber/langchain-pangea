from __future__ import annotations

import itertools
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from langchain_core.load import dumpd
from langchain_core.tracers import BaseTracer
from langchain_core.tracers.schemas import Run
from pangea.services import Audit

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from uuid import UUID

    from langchain_core.documents import Document
    from langchain_core.messages import BaseMessage
    from pangea import PangeaConfig
    from pydantic import SecretStr


def _get_run_type(run: Run) -> str:
    if isinstance(run.run_type, str):
        return run.run_type
    elif hasattr(run.run_type, "value"):
        return run.run_type.value
    else:
        return str(run.run_type)


class PangeaAuditLogTracer(BaseTracer):
    """Tracer that logs audit log events in Pangea's Secure Audit Log Schema."""

    _client: Audit

    def __init__(
        self,
        *,
        pangea_token: SecretStr,
        config: PangeaConfig | None = None,
        config_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Args:
            token: Pangea Secure Audit Log API token.
            config_id: Pangea Secure Audit Log configuration ID.
            domain: Pangea API domain.
        """

        super().__init__(**kwargs)
        self._metadata = metadata or {}
        self._client = Audit(token=pangea_token.get_secret_value(), config=config, config_id=config_id)

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[BaseMessage]],
        *,
        run_id: UUID,
        tags: list[str] | None = None,
        parent_run_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
        name: str | None = None,
        **kwargs: Any,
    ) -> Run:
        """Start a trace for an LLM run.

        Args:
            serialized: The serialized model.
            messages: The messages.
            run_id: The run ID.
            tags: The tags. Defaults to None.
            parent_run_id: The parent run ID. Defaults to None.
            metadata: The metadata. Defaults to None.
            name: The name. Defaults to None.
            kwargs: Additional keyword arguments.

        Returns:
            Run: The run.
        """
        start_time = datetime.now(UTC)
        if metadata:
            kwargs.update({"metadata": metadata})

        chat_model_run = Run(
            id=run_id,
            parent_run_id=parent_run_id,
            serialized=serialized,
            inputs={"messages": [[dumpd(msg) for msg in batch] for batch in messages]},
            extra=kwargs,
            events=[{"name": "start", "time": start_time}],
            start_time=start_time,
            run_type="llm",
            tags=tags,
            name=name,  # type: ignore[arg-type]
        )
        self._start_trace(chat_model_run)
        self._on_chat_model_start(chat_model_run)
        return chat_model_run

    def _convert_run_to_audit_schema(self, run: Run) -> dict[str, Any]:
        """
        Convert a Run to a dictionary that can be passed to the Pangea Audit Log API.
        """
        status: Literal["error", "success", "benign", "malicious"] = "error" if run.error else "success"
        findings, status = self._populate_aiguard_findings(run, status)
        output = self._process_outputs(run)
        input = self._process_inputs(run)
        type = _get_run_type(run)

        audit_dict: dict[str, Any] = {
            "start_time": run.start_time,
            "end_time": run.end_time,
            "trace_id": run.id,
            "type": type,
            "citations": run.name,
            "status": status,
            "input": input,
            "output": output,
            "findings": findings,
            "tools": self._process_audit_tools(run),
            "model": self._process_audit_model_info(run),
            "extra_info": run.metadata,
            "context": self._metadata.get("context", "none"),
            "authn_info": self._metadata.get("authn_info", "none"),
            "authz_info": self._metadata.get("authz_info", "none"),
            "actor": self._metadata.get("actor", "unknown"),
            "geolocation": self._metadata.get("geolocation", "unknown"),
            "source": self._metadata.get("source", "unknown"),
            "tenant_id": self._metadata.get("tenant_id", "unknown"),
        }
        return audit_dict

    def _populate_aiguard_findings(
        self, run: Run, status: Literal["error", "success", "benign", "malicious"]
    ) -> tuple[dict[str, Any], Literal["error", "success", "benign", "malicious"]]:
        """
        Populate AI Guard findings.
        """
        findings: dict[str, Any] = {}

        if run.name != "pangea-ai-guard-tool":
            return findings, status

        try:
            result = json.loads(run.outputs.get("output", "") if run.outputs else "")
            findings = result.get("findings", {})
            malicious_count = findings.get("malicious_count", None)

            # update status based on malicious count
            if malicious_count is None:
                status = "benign"
            else:
                status = "malicious" if malicious_count > 0 else "benign"

        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Error in _populate_aiguard_findings: {e}")

        return findings, status

    def _process_tool_inputs(self, run: Run) -> str:
        """Process the inputs."""
        return run.inputs["input"]

    def _process_llm_inputs(self, run: Run) -> str:
        """Process the inputs."""
        return run.inputs["messages"][0][0]["kwargs"]["content"]

    def _process_retriever_inputs(self, run: Run) -> str:
        """Process the inputs."""
        return run.inputs["query"]

    def _process_inputs(self, run: Run) -> str:
        """Process the inputs."""
        audit_input = ""
        run_type = _get_run_type(run)

        if run_type == "llm":
            audit_input = self._process_llm_inputs(run)
        elif run_type == "tool":
            audit_input = self._process_tool_inputs(run)
        elif run_type == "retriever":
            audit_input = self._process_retriever_inputs(run)
        else:
            audit_input = run.inputs.get("input", "")
            if not isinstance(audit_input, str):
                audit_input = audit_input.content
        return audit_input

    def _process_tool_outputs(self, run: Run) -> str:
        """Process the tool outputs."""
        if run.outputs is not None:
            if run.name == "pangea-ai-guard-tool":
                return json.loads(run.outputs.get("output", "")).get("redacted_prompt", "")
            else:
                return run.outputs.get("output", "")
        return ""

    def _string_to_json(self, input_string: str) -> dict:
        try:
            return json.loads(input_string)
        except json.JSONDecodeError:
            return {"answer": input_string}

    def _process_llm_outputs(self, run: Run) -> Any:
        """Process the llm outputs."""

        if not run.outputs:
            return ""

        if "generations" not in run.outputs:
            return ""

        generations: Iterable[Mapping[str, Any]] = itertools.chain.from_iterable(run.outputs["generations"])
        text_generations: list[str] = [x["text"] for x in generations if "text" in x]

        if len(text_generations) == 0:
            return ""

        # return self._string_to_json(text_generations[0])
        return text_generations[0]

    def _process_retriever_outputs(self, run: Run) -> str:
        """Process the retriever outputs."""
        if run.outputs is not None:
            documents: list[Document] = run.outputs.get("documents", [])
            docs_list = [{"page_content": doc.page_content, "metadata": doc.metadata} for doc in documents]
            return json.dumps(docs_list)
        return ""

    def _process_outputs(self, run: Run) -> Any:
        """Process the outputs."""
        audit_output = ""
        run_type = _get_run_type(run)
        if run_type == "llm":
            audit_output = self._process_llm_outputs(run)
        elif run_type == "tool":
            audit_output = self._process_tool_outputs(run)
        elif run_type == "retriever":
            audit_output = self._process_retriever_outputs(run)
        # else:
        #     audit_output = run.outputs.get("output", "")

        return audit_output

    def _process_audit_model_info(self, run: Run) -> dict:
        """Process the LLM audit tool."""
        models: dict = {}
        if _get_run_type(run) == "llm":
            if run.serialized is not None:
                models["provider"] = run.serialized["name"]
                if "model_id" in run.serialized["kwargs"]:
                    models[f"{_get_run_type(run)}"] = run.serialized["kwargs"]["model_id"]
        return models

    def _process_audit_tools(self, run: Run) -> dict:
        """Process the tools."""
        audit_tools: dict = {}
        type = _get_run_type(run)
        # if _get_run_type(run) == "llm":
        #     audit_tools = self._process_audit_model_info(run)
        if type in {"tool", "retriever"}:
            audit_tools = {f"{type}": f"{run.name}"}
        return audit_tools

    def _add_audit_log(self, run: Run) -> None:
        """Add audit log event."""
        audit_dict = self._convert_run_to_audit_schema(run)

        if _get_run_type(run) != "chain":
            try:
                self._client.log_bulk([audit_dict])
            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"Error in _add_audit_log: {e}")

    def _persist_run(self, run: Run) -> None:
        pass

    # def _on_llm_start(self, run: Run) -> None:
    #     """Process the LLM Run upon start."""
    # self._add_audit_log(run)

    # def _on_chat_model_start(self, run: Run) -> None:
    #     """Process the LLM Run upon start."""
    # self._add_audit_log(run)

    def _on_llm_end(self, run: Run) -> None:
        """Process the LLM Run."""
        self._add_audit_log(run)

    def _on_llm_error(self, run: Run) -> None:
        """Process the LLM Run upon error."""
        self._add_audit_log(run)

    # def _on_chain_start(self, run: Run) -> None:
    # """Process the Chain Run upon start."""
    # self._add_audit_log(run)

    # def _on_chain_end(self, run: Run) -> None:
    #     """Process the Chain Run."""
    #     self._add_audit_log(run)

    def _on_chain_error(self, run: Run) -> None:
        """Process the Chain Run upon error."""
        self._add_audit_log(run)

    # def _on_tool_start(self, run: Run) -> None:
    #     """Process the Tool Run upon start."""
    # self._add_audit_log(run)

    def _on_tool_end(self, run: Run) -> None:
        """Process the Tool Run."""
        self._add_audit_log(run)

    def _on_tool_error(self, run: Run) -> None:
        """Process the Tool Run upon error."""
        self._add_audit_log(run)

    # def _on_retriever_start(self, run: Run) -> None:
    #     """Process the Retriever Run upon start."""
    #     self._add_audit_log(run)

    def _on_retriever_end(self, run: Run) -> None:
        """Process the Retriever Run."""
        self._add_audit_log(run)

    def _on_retriever_error(self, run: Run) -> None:
        """Process the Retriever Run upon error."""
        self._add_audit_log(run)
