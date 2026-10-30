"""Safe diagnostics shared by command-line entry points."""
from __future__ import annotations

import json
import re
import subprocess

import yaml


class InputError(ValueError):
    """An input error whose message contains no raw subscription content."""


class OperationError(RuntimeError):
    """A controlled business failure with an actionable, non-secret message."""


def parse_error_summary(error: Exception) -> str:
    detail = type(error).__name__
    mark = getattr(error, "problem_mark", None)
    if mark is not None:
        return f"{detail}, line {mark.line + 1}, column {mark.column + 1}"
    if isinstance(error, json.JSONDecodeError):
        return f"{detail}, line {error.lineno}, column {error.colno}"
    return detail


def safe_error_message(error: Exception) -> str:
    if isinstance(error, (yaml.YAMLError, json.JSONDecodeError, UnicodeError)):
        return f"输入格式无效（{parse_error_summary(error)}）；请检查对应本地文件，原始内容未输出。"
    if isinstance(error, subprocess.TimeoutExpired):
        return "核心校验超时；请检查核心状态后重试。"
    if isinstance(error, subprocess.SubprocessError):
        return "核心命令执行失败；命令参数和输出已隐藏。"
    if isinstance(error, OSError):
        return f"文件或系统操作失败（{type(error).__name__}, code={error.errno}）；请检查路径、权限和剩余空间。"
    if isinstance(error, (KeyError, TypeError)) or (isinstance(error, RuntimeError) and not isinstance(error, OperationError)):
        return f"处理失败（{type(error).__name__}）；请检查输入和活动版本状态，原始异常内容未输出。"
    # URI values may contain credentials even without a token query parameter.
    message = re.sub(r"[A-Za-z][A-Za-z0-9+.-]*://\S+", "[链接已隐藏]", str(error))
    return " ".join(message.split())[:600] or type(error).__name__
