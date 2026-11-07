def _spoke_impl(rctx):
    rctx.file("data.txt", rctx.attr.version)
    rule_name = "sdk_crate" if rctx.attr.uses_sdk else "crate"
    rctx.file("BUILD.bazel", """load("@ext//:defs.bzl", crate = "{rule}")
crate(name = "lib", srcs = ["data.txt"], visibility = ["//visibility:public"])
""".format(rule = rule_name))

spoke = repository_rule(
    implementation = _spoke_impl,
    attrs = {"uses_sdk": attr.bool(), "version": attr.string()},
)

def _sdk_impl(rctx):
    rctx.file("BUILD.bazel", """load("@ext//:defs.bzl", "sdk")
sdk(name = "impl", version = "{version}")
toolchain(name = "registration", toolchain = ":impl", toolchain_type = "@ext//:sdk_type")
""".format(version = rctx.attr.version))

sdk_repo = repository_rule(implementation = _sdk_impl, attrs = {"version": attr.string()})

def _hub_impl(rctx):
    rctx.file("BUILD.bazel", "\n".join([
        'alias(name = "{0}", actual = "@crates__{0}//:lib", visibility = ["//visibility:public"])'.format(name)
        for name in rctx.attr.names
    ]))

hub = repository_rule(implementation = _hub_impl, attrs = {"names": attr.string_list()})

def _crates_impl(mctx):
    versions = {}
    for mod in mctx.modules:
        for lock in mod.tags.lock:
            versions.update(json.decode(mctx.read(lock.file)))
    sdk_version = versions.pop("sdk", None)
    if sdk_version != None:
        sdk_repo(name = "sdk_provider", version = sdk_version)
    for name, version in versions.items():
        spoke(name = "crates__" + name, version = version, uses_sdk = sdk_version != None)
    hub(name = "crates", names = sorted(versions))
    hub(name = "ext_tools", names = [])

crates = module_extension(
    implementation = _crates_impl,
    tag_classes = {"lock": tag_class(attrs = {"file": attr.label()})},
)
