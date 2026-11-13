def _app(ctx):
    ctx.file("BUILD.bazel", """load("@ext//:defs.bzl", "library", "metadata")
package(default_visibility = ["//visibility:public"])
library(name = "lib")
metadata(name = "metadata")
alias(name = "forward", actual = ":lib")
""")

app = repository_rule(implementation = _app)

def _hub(ctx):
    ctx.file("BUILD.bazel", """package(default_visibility = ["//visibility:public"])
alias(name = "metadata", actual = "@app//:metadata")
alias(name = "compiler", actual = "@app//:forward")
alias(name = "sibling", actual = "@sibling//:version.txt")
alias(name = "compiler_version", actual = "@tc_impl//:version.txt")
alias(name = "copied", actual = "@derived//:library")
""")

hub = repository_rule(implementation = _hub)

def _tool(ctx):
    data = ctx.read(ctx.attr.source) if ctx.attr.source else ctx.attr.version
    ctx.file("version.txt", data, executable = False)
    ctx.file("BUILD.bazel", """load("@ext//:defs.bzl", "compiler")
exports_files(["version.txt"])
compiler(name = "impl", runtime = ":version.txt")
toolchain(name = "tc", toolchain = ":impl", toolchain_type = "@ext//:toolchain_type", visibility = ["//visibility:public"])
""")

tool = repository_rule(implementation = _tool, attrs = {"source": attr.label(), "version": attr.string()})

def _derived(ctx):
    ctx.file("BUILD.bazel", 'load(":generated.bzl", "generated")\ngenerated(name = "library", visibility = ["//visibility:public"])\n')
    ctx.file("generated.bzl", """def _impl(ctx):
    out = ctx.actions.declare_file("result.txt")
    ctx.actions.write(out, {value})
    return [DefaultInfo(files = depset([out]))]
generated = rule(implementation = _impl)
""".format(value = repr(ctx.read(ctx.attr.data))))

derived = repository_rule(implementation = _derived, attrs = {"data": attr.label()})

def _tools(ctx):
    versions = {}
    for mod in ctx.modules:
        for lock in mod.tags.lock:
            versions.update(json.decode(ctx.read(lock.file)))
    app(name = "app")
    hub(name = "hub")
    tool(name = "tc", version = "default")
    tool(name = "tc_impl", source = "@@//:compiler-input.txt")
    tool(name = "sibling", version = versions["sibling"])
    derived(name = "derived", data = "@sibling//:version.txt")

tools = module_extension(
    implementation = _tools,
    tag_classes = {"lock": tag_class(attrs = {"file": attr.label()})},
)
