"""Faramesh framework adapters — deeper integrations beyond auto-patching."""

from .langchain import install, install_langchain_interceptor

__all__ = [
	"install",
	"install_langchain_interceptor",
]
