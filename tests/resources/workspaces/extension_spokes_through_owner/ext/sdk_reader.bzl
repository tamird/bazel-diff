def _sdk_impl(ctx):
    return [platform_common.ToolchainInfo(data = ctx.file.data)]

sdk = rule(
    implementation = _sdk_impl,
    attrs = {"data": attr.label(allow_single_file = True)},
)

def _sdk_reader_impl(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.expand_template(
        template = ctx.toolchains["@@//:sdk_type"].data,
        output = output,
        substitutions = {},
    )
    return [DefaultInfo(files = depset([output]))]

sdk_reader = rule(
    implementation = _sdk_reader_impl,
    attrs = {"srcs": attr.label_list(allow_files = True)},
    toolchains = ["@@//:sdk_type"],
)
