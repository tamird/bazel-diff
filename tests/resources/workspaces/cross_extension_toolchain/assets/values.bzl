"""Generate two independent file repositories."""

def _file(ctx):
    ctx.file("BUILD.bazel", 'exports_files(["value.txt"])')
    ctx.file("value.txt", ctx.attr.value)

_value = repository_rule(implementation = _file, attrs = {"value": attr.string()})

def _values(ctx):
    for module in ctx.modules:
        for tag in module.tags.versions:
            for name, value in json.decode(ctx.read(tag.file)).items():
                _value(name = name, value = value)

values = module_extension(
    implementation = _values,
    tag_classes = {"versions": tag_class(attrs = {"file": attr.label()})},
)
