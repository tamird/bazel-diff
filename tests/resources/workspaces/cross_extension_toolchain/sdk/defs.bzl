"""Expose the payload declared by the selected toolchain."""

def _tool(ctx):
    return [platform_common.ToolchainInfo(payload = ctx.file.payload)]

sdk_tool = rule(implementation = _tool, attrs = {"payload": attr.label(allow_single_file = True)})

def _consumer(ctx):
    payload = ctx.toolchains["@sdk//:type"].payload
    out = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.run_shell(
        inputs = [payload],
        outputs = [out],
        arguments = [payload.path, out.path],
        command = 'cat "$1" > "$2"',
    )
    return [DefaultInfo(files = depset([out]))]

consumer = rule(implementation = _consumer, toolchains = ["@sdk//:type"])
