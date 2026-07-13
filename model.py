"""LangChain model request client."""

from __future__ import annotations

from pathlib import Path
from typing import Generic, TypeVar

import yaml
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel


ResponseT = TypeVar("ResponseT", bound=BaseModel)


class PromptYamlDumper(yaml.SafeDumper):
    pass


def represent_prompt_string(dumper: yaml.Dumper, value: str) -> yaml.nodes.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


PromptYamlDumper.add_representer(str, represent_prompt_string)


class ModelClient(Generic[ResponseT]):
    """Only sends requests to the model and validates the JSON response."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        temperature: float,
        max_tokens: int,
        timeout: int,
        system_prompt: str,
        user_prompt: str,
        response_schema: type[ResponseT],
        max_retries: int = 3,
    ) -> None:
        if max_retries < 1:
            raise ValueError("max_retries must be >= 1")

        self.response_schema = response_schema
        self.max_retries = max_retries
        self.parser: JsonOutputParser = JsonOutputParser(pydantic_object=response_schema)
        self.prompt = ChatPromptTemplate.from_messages(
            [
                ("system", system_prompt),
                ("user", user_prompt),
            ],
            template_format="jinja2",
        ).partial(format_instructions=self.parser.get_format_instructions())
        self.model = ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url=base_url,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
        )
        self.chain = self.prompt | self.model | self.parser

    def request(self, source_json: str, prompt_output_path: str | Path | None = None) -> ResponseT:
        if prompt_output_path is not None:
            self.save_rendered_prompt(source_json, Path(prompt_output_path))

        last_error: Exception | None = None
        for _ in range(self.max_retries):
            try:
                parsed = self.chain.invoke({"source_json": source_json})
                return self.response_schema.model_validate(parsed)
            except Exception as error:
                last_error = error

        if last_error is None:
            raise RuntimeError("Model request failed without captured exception")
        raise last_error

    def save_rendered_prompt(self, source_json: str, path: Path) -> None:
        prompt_value = self.prompt.invoke({"source_json": source_json})
        messages: list[dict[str, str]] = []
        for message in prompt_value.to_messages():
            messages.append(
                {
                    "role": message.type,
                    "content": message.content,
                }
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.dump(
                {"messages": messages},
                Dumper=PromptYamlDumper,
                allow_unicode=True,
                sort_keys=False,
                width=120,
            ),
            encoding="utf-8",
        )
