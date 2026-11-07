"""A toolchain consumer and a holder that only reads the declaration's binding."""

BindingInfo = provider(
    doc = "The implementation label stored in a toolchain declaration.",
    fields = {"label": "The implementation label as a string."},
)

def _binding(_, ctx):
    return [BindingInfo(label = str(ctx.rule.attr.toolchain))]

binding = aspect(implementation = _binding)

def _prefer(_, attr):
    return {"//command_line_option:extra_toolchains": [str(attr.registration)]}

prefer = transition(
    implementation = _prefer,
    inputs = [],
    outputs = ["//command_line_option:extra_toolchains"],
)

def _tool(ctx):
    return [platform_common.ToolchainInfo(payload = ctx.file.payload)]

tool = rule(implementation = _tool, attrs = {"payload": attr.label(allow_single_file = True)})

def _hold(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.write(out, ctx.attr.registration[BindingInfo].label)
    return [DefaultInfo(files = depset([out, ctx.file.other]))]

def _read(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.symlink(output = out, target_file = ctx.toolchains["//:type"].payload)
    return [DefaultInfo(files = depset([out]))]

allowlist = attr.label(default = "@bazel_tools//tools/allowlists/function_transition_allowlist")

holder = rule(
    implementation = _hold,
    attrs = {
        "other": attr.label(allow_single_file = True),
        "registration": attr.label(aspects = [binding]),
        "_allowlist_function_transition": allowlist,
    },
    cfg = prefer,
)
reader = rule(
    implementation = _read,
    attrs = {"registration": attr.string(default = "//:available"), "_allowlist_function_transition": allowlist},
    cfg = prefer,
    toolchains = ["//:type"],
)
ordinary_reader = rule(implementation = _read, toolchains = ["//:type"])

# On producers without declared-type information, the registration input was
# also the only ordinary route to this consumer's selected implementation.
explicit_reader = rule(
    implementation = _read,
    attrs = {"registration": attr.label(), "_allowlist_function_transition": allowlist},
    cfg = prefer,
    toolchains = ["//:type"],
)

def _forward(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.symlink(output = out, target_file = ctx.file.child)
    return [DefaultInfo(files = depset([out]))]

forward = rule(
    implementation = _forward,
    attrs = {
        "child": attr.label(allow_single_file = True, cfg = prefer),
        "registration": attr.label(),
        "_allowlist_function_transition": allowlist,
    },
)
