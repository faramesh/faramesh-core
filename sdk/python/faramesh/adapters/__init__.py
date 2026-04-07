"""Faramesh framework adapters — deeper integrations beyond auto-patching."""

from .deepagents import install_deepagents_interceptor
from .langchain import install, install_langchain_interceptor

__all__ = [
	"install",
	"install_deepagents_interceptor",
	"install_langchain_interceptor",
]
