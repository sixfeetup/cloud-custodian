#!/usr/bin/env python3
# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""List Bedrock-eligible SageMaker JumpStart models, split by EULA requirement.

Helps pick a MARKETPLACE_MODEL_SOURCE_IDENTIFIER for
tests/test_bedrock_marketplace.py. There is no API field marking a model
"free" -- this lists every model Bedrock's console exposes (search keyword
``@capability:bedrock_console``) and separates those that need
``acceptEula`` (still free, just gated) from those that don't. Models sold
through AWS Marketplace as paid, private-offer listings aren't
distinguishable through this API and must be recognized by name; run
``describe-hub-content`` on a candidate and check its pricing/vendor terms
before using it if in doubt.

Also prints ``HubContentDocument.BedrockIOMappingId``, the I/O contract ID
Bedrock uses to invoke the model, and a derived ``converse`` guess. The
mapping ID is always present -- it's the *value* that signals Converse
support: multi-turn/structured contracts (containing "chat", "messages", or
"tools", for example ``tgi_im-chat-template_1.0.0`` or ``tgi_tools_1.0.0``)
support ``converse``, while ``tgi_default_1.0.0`` and similar
plain-completion contracts don't. This is a heuristic on the mapping ID
rather than a documented contract, so treat ``--require-converse`` as a
strong hint, not a guarantee -- verify a chosen model against AWS's
published compatibility table (bedrock-marketplace-model-reference.html)
before committing to it.

Also prints ``DefaultInferenceInstanceType`` and
``SupportedInferenceInstanceTypes`` from the same document, so
MARKETPLACE_ENDPOINT_INSTANCE_TYPE in tests/test_bedrock_marketplace.py can
be set to a value the model actually supports instead of guessed.
"""

import json

import boto3
import click

HUB_NAME = "SageMakerPublicHub"
BEDROCK_CONSOLE_KEYWORD = "@capability:bedrock_console"


def list_bedrock_models(client, name_contains=None):
    # list_hub_contents has no paginator config; page manually via NextToken.
    kwargs = {"HubName": HUB_NAME, "HubContentType": "Model", "MaxResults": 100}
    if name_contains:
        kwargs["NameContains"] = name_contains
    while True:
        response = client.list_hub_contents(**kwargs)
        for summary in response["HubContentSummaries"]:
            if BEDROCK_CONSOLE_KEYWORD in summary.get("HubContentSearchKeywords", []):
                yield summary
        next_token = response.get("NextToken")
        if not next_token:
            return
        kwargs["NextToken"] = next_token


def describe_model_document(client, name, version):
    detail = client.describe_hub_content(
        HubName=HUB_NAME, HubContentType="Model",
        HubContentName=name, HubContentVersion=version,
    )
    return json.loads(detail["HubContentDocument"])


CONVERSE_IO_MAPPING_TOKENS = ("chat", "messages", "tools")


def supports_converse(io_mapping):
    lowered = io_mapping.lower()
    return any(token in lowered for token in CONVERSE_IO_MAPPING_TOKENS)


@click.command()
@click.option("--region", default="us-east-1", show_default=True)
@click.option(
    "--eula-status", type=click.Choice(("all", "no-eula", "eula")), default="all",
    show_default=True, help="Filter by whether the model requires acceptEula")
@click.option(
    "--name-contains", multiple=True,
    help="Substring filter on HubContentName (server-side per value), e.g. "
         "--name-contains gpt-oss --name-contains mistral. Repeatable; "
         "matches models containing any given value. Note: Claude isn't "
         "distributed through this hub -- Bedrock serves it as a native "
         "foundation model, not a JumpStart/Marketplace endpoint.")
@click.option(
    "--require-converse", is_flag=True,
    help="Only show models whose BedrockIOMappingId looks chat-formatted "
         "(heuristic for Converse API support -- see module docstring).")
def main(region, eula_status, name_contains, require_converse):
    client = boto3.client("sagemaker", region_name=region)

    terms = name_contains or (None,)

    seen = set()
    for term in terms:
        for model in list_bedrock_models(client, name_contains=term):
            if model["HubContentArn"] in seen:
                continue
            seen.add(model["HubContentArn"])

            name = model["HubContentName"]
            version = model["HubContentVersion"]
            document = describe_model_document(client, name, version)
            gated = bool(document.get("HostingEulaUri"))
            io_mapping = document.get("BedrockIOMappingId", "")
            converse = supports_converse(io_mapping)
            default_instance = document.get("DefaultInferenceInstanceType", "-")
            supported_instances = document.get("SupportedInferenceInstanceTypes") or []

            if eula_status == "no-eula" and gated:
                continue
            if eula_status == "eula" and not gated:
                continue
            if require_converse and not converse:
                continue

            click.echo(
                f"{name}\t{version}\teula={gated}\tconverse={converse}\t"
                f"io_mapping={io_mapping or '-'}\tdefault_instance={default_instance}\t"
                f"supported_instances={','.join(supported_instances) or '-'}\t"
                f"{model['HubContentArn']}")


if __name__ == "__main__":
    main()
