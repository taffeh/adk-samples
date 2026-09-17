import os
import logging
from typing import Optional
from dotenv import load_dotenv

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types

logger = logging.getLogger(__name__)
load_dotenv()


AIRS_ENABLED = os.getenv("AIRS_ENABLED", "false").lower() == "true"
AIRS_APPNAME = os.getenv("AIRS_APPNAME", "NEW_APP")
AIRS_CA_BUNDLE = os.getenv("AIRS_CA_BUNDLE")
AIRS_API_KEY = os.getenv("PANW_AI_SEC_API_KEY") or os.getenv("AIRS_API_KEY")
AIRS_API_ENDPOINT = (
    os.getenv("PANW_AI_SEC_API_ENDPOINT")
    or os.getenv("AIRS_API_ENDPOINT")
    or "https://service-de.api.aisecurity.paloaltonetworks.com"
)

if AIRS_CA_BUNDLE:
    os.environ["SSL_CERT_FILE"] = AIRS_CA_BUNDLE
    os.environ["REQUESTS_CA_BUNDLE"] = AIRS_CA_BUNDLE


if AIRS_ENABLED:
    try:
        import aisecurity
        from aisecurity.scan.inline.scanner import Scanner
        from aisecurity.scan.models.content import Content
        from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
        from aisecurity.generated_openapi_client.models.metadata import Metadata

        if AIRS_CA_BUNDLE:
            logger.info("AIRS using custom CA bundle %s", AIRS_CA_BUNDLE)

        aisecurity.init(
            api_key=AIRS_API_KEY,
            api_endpoint=AIRS_API_ENDPOINT,
        )
            
        _scanner   = Scanner()
        _ai_profile = AiProfile(
            profile_name=os.getenv("AIRS_PROFILE_NAME", "Default")
        )
        logger.info("AIRS enabled — scanner initialised")
    except Exception as e:
        logger.error(f"AIRS init failed: {e}. Defaulting to fail-open.")
        AIRS_ENABLED = False
else:
    alert= os.getenv("AIRS_ENABLED","__not_provided__")
    logger.warning(f"AIRS not enabled via env, \"{alert}\"")

def _extract_prompt(llm_request: LlmRequest) -> str:
    for content in reversed(llm_request.contents or []):
        if content.role == "user":
            return " ".join(
                p.text for p in (content.parts or []) if getattr(p, "text")
            )
    return ""


def _extract_response(llm_response: LlmResponse) -> str:
    if llm_response.content and llm_response.content.parts:
        return " ".join(
            p.text for p in llm_response.content.parts if getattr(p, "text")
        )
    return ""


def _blocked_response(reason: str) -> LlmResponse:
    return LlmResponse(
        content=types.Content(
            role="model",
            parts=[types.Part(
                text=f"I cannot process that request. [AIRS: {reason}]"
            )],
        )
    )


def before_model_callback(
    callback_context: CallbackContext,
    llm_request: LlmRequest,
) -> Optional[LlmResponse]:
    """Scan prompt before it reaches the LLM. Fail-closed on error."""

    if not AIRS_ENABLED:
        return None

    prompt_text = _extract_prompt(llm_request)
    if not prompt_text:
        return None

    try:
        result = _scanner.sync_scan(
            ai_profile=_ai_profile,
            content=Content(prompt=prompt_text),
            session_id=callback_context.session.id,
            metadata= Metadata(
                app_name=f"{AIRS_APPNAME}-{callback_context.agent_name}",
                ai_model=llm_request.model,
                app_user=callback_context.state.get("user_id", "demo-user"),
            ),
        )

        # Persist to session state for audit trail
        callback_context.state["airs_prompt_scan"] = {
            "agent":    callback_context.agent_name,
            "action":   result.action,
            "category": result.category,
            "scan_id":  result.scan_id,
            "session_id": result.session_id,
            "prompt_detected": result.prompt_detected.to_dict() if result.prompt_detected else None,
        }

        if result.action == "block":
            logger.warning(
                f"AIRS blocked prompt | agent={callback_context.agent_name} "
                f"category={result.category} scan_id={result.scan_id}"
            )
            return _blocked_response(result.category)
        else:
            logger.warning(
                f"AIRS allowed prompt | agent={callback_context.agent_name}"
                f"category={result.category} scan_id={result.scan_id}"
            )

    except Exception as e:
        # Fail-closed — do not allow unscanned content through
        logger.error(f"AIRS before_model_callback error: {e}")
        callback_context.state["airs_prompt_scan_error"] = str(e)
        return _blocked_response("security check unavailable")

    return None


def after_model_callback(
    callback_context: CallbackContext,
    llm_response: LlmResponse,
) -> Optional[LlmResponse]:
    """Scan model response before it leaves the agent. Fail-closed on error."""

    if not AIRS_ENABLED:
        return None

    response_text = _extract_response(llm_response)
    if not response_text:
        return None

    try:
        result = _scanner.sync_scan(
            ai_profile=_ai_profile,
            content=Content(response=response_text),
            session_id = callback_context.session.id,
            metadata=Metadata(
            app_name=f"{AIRS_APPNAME}-{callback_context.agent_name}",
            #ai_model=callback_context.state.get("_airs_model_name","unknown"),
            app_user=callback_context.state.get("user_id", "demo-user"),
    ),
        )

        callback_context.state["airs_response_scan"] = {
            "agent":    callback_context.agent_name,
            "action":   result.action,
            "category": result.category,
            "scan_id":  result.scan_id,
            "session_id": result.session_id,
            "response_detected": result.response_detected.to_dict() if result.response_detected else None,
        }

        if result.action == "block":
            logger.warning(
                f"AIRS blocked response | agent={callback_context.agent_name} "
                f"category={result.category} scan_id={result.scan_id}"
            )
            return _blocked_response(result.category)
        else:
            logger.warning(
                f"AIRS allowed response | agent={callback_context.agent_name}"
                f"category={result.category} scan_id={result.scan_id}"
            )

    except Exception as e:
        logger.error(f"AIRS after_model_callback error: {e}")
        callback_context.state["airs_response_scan_error"] = str(e)
        return _blocked_response("security check unavailable")

    return None
