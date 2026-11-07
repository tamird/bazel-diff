def _crate_impl(ctx):
    return [DefaultInfo(files = depset(ctx.files.srcs))]

_SRC_ATTRS = {
    "srcs": attr.label_list(allow_files = True),
    "_tool": attr.label(default = "@ext//:tool.sh", allow_single_file = True),
}

crate = rule(implementation = _crate_impl, attrs = _SRC_ATTRS)

def _sdk_crate_impl(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.run_shell(
        inputs = ctx.files.srcs,
        outputs = [output],
        arguments = [ctx.files.srcs[0].path, ctx.toolchains["@ext//:sdk_type"].version, output.path],
        command = 'cat "$1" > "$3" && printf "|%s" "$2" >> "$3"',
    )
    return [DefaultInfo(files = depset([output]))]

sdk_crate = rule(
    implementation = _sdk_crate_impl,
    attrs = _SRC_ATTRS,
    toolchains = ["@ext//:sdk_type"],
)

def _sdk(ctx):
    return [platform_common.ToolchainInfo(version = ctx.attr.version)]

sdk = rule(implementation = _sdk, attrs = {"version": attr.string(mandatory = True)})
