load("@@//definitions:marker.bzl", "MARKER")

def _compiler(ctx):
    return [platform_common.ToolchainInfo(runtime = ctx.file.runtime)]

compiler = rule(
    implementation = _compiler,
    attrs = {"runtime": attr.label(allow_single_file = True)},
)

def _library(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.symlink(output = out, target_file = ctx.toolchains["@ext//:toolchain_type"].runtime)
    return [DefaultInfo(files = depset([out]))]

library = rule(implementation = _library, toolchains = ["@ext//:toolchain_type"])

def _metadata(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.write(out, MARKER)
    return [DefaultInfo(files = depset([out]))]

metadata = rule(implementation = _metadata)
