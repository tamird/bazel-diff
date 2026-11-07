"""Declare the registered provider in a separate generated repository."""

def _registration(ctx):
    ctx.file("BUILD.bazel", """load("@sdk//:defs.bzl", "sdk_tool")
sdk_tool(name = "impl", payload = "@assets//:payload")
toolchain(name = "registered", toolchain = ":impl", toolchain_type = "@sdk//:type")
""")

_registration_repo = repository_rule(implementation = _registration)

def _tools(_ctx):
    _registration_repo(name = "sdk_registration")

tools = module_extension(implementation = _tools)
