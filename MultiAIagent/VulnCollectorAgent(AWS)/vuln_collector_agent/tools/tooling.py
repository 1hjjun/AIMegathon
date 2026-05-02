from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


def tool(func: F) -> F:
    return func
