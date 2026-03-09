"""
Faramesh Python SDK — A1 (SDK Shim) adapter.

One import. One decorator. Governance in 60 seconds.

    pip install faramesh

    from faramesh import govern

    governed_refund = govern(stripe_refund, policy='payment.yaml', agent_id='payment-bot')
    # govern() auto-starts the faramesh daemon on first call.
    # Preserves type hints, Pydantic models, LangChain @tool metadata, docstrings.
    # Raises DenyError on DENY, DeferredError (blocking) on DEFER.
"""

from .govern import govern
from .client import FarameshClient
from .exceptions import DenyError, DeferredError, FarameshError

__version__ = "0.1.0"
__all__ = ["govern", "FarameshClient", "DenyError", "DeferredError", "FarameshError"]
