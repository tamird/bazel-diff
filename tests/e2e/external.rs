use crate::support::*;
use std::collections::BTreeSet;
use std::fs;

fn zipped_golden_case(first_zip: &str, second_zip: &str, generate_args: &[&str], golden: &str) {
    let first = extract_fixture(first_zip);
    let second = extract_fixture(second_zip);
    let output = tempfile::tempdir().unwrap();
    let from = output.path().join("from.json");
    let to = output.path().join("to.json");
    let result = output.path().join("impacted.txt");
    assert!(generate(first.path(), &from, generate_args)
        .status
        .success());
    assert!(generate(second.path(), &to, generate_args).status.success());
    assert!(impacted(second.path(), &from, &to, &result, &[])
        .status
        .success());
    assert_eq!(
        filter_internal(read_lines(&result)),
        filter_internal(golden_lines(golden))
    );
}

#[test]
fn fine_grained_workspace_external_repo() {
    zipped_golden_case(
        "fine-grained-hash-external-repo-test-1.zip",
        "fine-grained-hash-external-repo-test-2.zip",
        &["--fineGrainedHashExternalRepos", "@bazel_diff_maven"],
        "fine-grained-hash-external-repo-test-impacted-targets.txt",
    );
}

#[test]
fn fine_grained_bzlmod_repo() {
    zipped_golden_case(
        "fine-grained-hash-bzlmod-test-1.zip",
        "fine-grained-hash-bzlmod-test-2.zip",
        &["--fineGrainedHashExternalRepos", "@bazel_diff_maven"],
        "fine-grained-hash-bzlmod-test-impacted-targets.txt",
    );
}

#[test]
fn fine_grained_bzlmod_repo_cquery() {
    zipped_golden_case(
        "fine-grained-hash-bzlmod-test-1.zip",
        "fine-grained-hash-bzlmod-test-2.zip",
        // The apparent name, as the query-mode case passes: it names the same repository on
        // every Bazel version, where the canonical spelling changed from `~~maven~maven`
        // (Bazel 7) to `++maven+maven` (Bazel 8). With cquery's canonical labels now reaching
        // the `//external:bazel_diff_maven` node, a flag that names nothing makes the lock-file
        // change fan out to every maven consumer instead of the fine-grained set.
        &[
            "--fineGrainedHashExternalRepos",
            "@bazel_diff_maven",
            "--useCquery",
        ],
        "fine-grained-hash-bzlmod-cquery-test-impacted-targets.txt",
    );
}

#[test]
fn bzlmod_transitive_deps_query() {
    zipped_golden_case(
        "bzlmod-transitive-test-1.zip",
        "bzlmod-transitive-test-2.zip",
        &["--fineGrainedHashExternalRepos", "@bazel_diff_maven"],
        "bzlmod-transitive-test-impacted-targets.txt",
    );
}

#[test]
fn bzlmod_transitive_deps_cquery() {
    zipped_golden_case(
        "bzlmod-transitive-test-1.zip",
        "bzlmod-transitive-test-2.zip",
        // Apparent name for the same reason as fine_grained_bzlmod_repo_cquery.
        &[
            "--fineGrainedHashExternalRepos",
            "@bazel_diff_maven",
            "--useCquery",
        ],
        "bzlmod-transitive-test-cquery-impacted-targets.txt",
    );
}

#[test]
#[ignore = "fixture pins Bazel 7 layout that is incompatible with Bazel 8+ tools/windows packaging"]
fn bzlmod_cc_transitive_deps_query() {
    zipped_golden_case(
        "bzlmod-cc-transitive-test-1.zip",
        "bzlmod-cc-transitive-test-2.zip",
        &[],
        "bzlmod-cc-transitive-test-impacted-targets.txt",
    );
}

fn cquery_platform_case(second_zip: &str, platform: &str, golden: &str) {
    let first = extract_fixture("cquery-test-base.zip");
    let second = extract_fixture(second_zip);
    let output = tempfile::tempdir().unwrap();
    let from = output.path().join("from.json");
    let to = output.path().join("to.json");
    let result = output.path().join("impacted.txt");
    let platform_arg = format!("--platforms=//:{platform}");
    let args = [
        "--useCquery",
        "--cqueryCommandOptions",
        platform_arg.as_str(),
        "--fineGrainedHashExternalRepos",
        "@@bazel_diff_maven,@@bazel_diff_maven_android",
    ];
    assert!(generate(first.path(), &from, &args).status.success());
    assert!(generate(second.path(), &to, &args).status.success());
    assert!(impacted(second.path(), &from, &to, &result, &[])
        .status
        .success());
    assert_eq!(
        filter_internal(read_lines(&result)),
        filter_internal(golden_lines(golden))
    );
}

#[test]
fn cquery_external_dependency_change_platforms() {
    cquery_platform_case(
        "cquery-test-guava-upgrade.zip",
        "android",
        "cquery-test-guava-upgrade-android-impacted-targets.txt",
    );
    cquery_platform_case(
        "cquery-test-guava-upgrade.zip",
        "jre",
        "cquery-test-guava-upgrade-jre-impacted-targets.txt",
    );
}

#[test]
fn cquery_android_source_change_platforms() {
    cquery_platform_case(
        "cquery-test-android-code-change.zip",
        "android",
        "cquery-test-android-code-change-android-impacted-targets.txt",
    );
    cquery_platform_case(
        "cquery-test-android-code-change.zip",
        "jre",
        "cquery-test-android-code-change-jre-impacted-targets.txt",
    );
}

#[test]
fn bzlmod_show_repo_and_external_filtering() {
    if !supports_mod_show_repo() {
        return;
    }
    let first = extract_fixture("bzlmod-show-repo-test-1.zip");
    let second = extract_fixture("bzlmod-show-repo-test-2.zip");
    let output = tempfile::tempdir().unwrap();
    let from = output.path().join("from.json");
    let to = output.path().join("to.json");
    let default_result = output.path().join("default.txt");
    let opt_out = output.path().join("opt-out.txt");
    assert!(generate(first.path(), &from, &[]).status.success());
    assert!(generate(second.path(), &to, &[]).status.success());
    assert!(impacted(second.path(), &from, &to, &default_result, &[])
        .status
        .success());
    let default_labels = read_lines(&default_result);
    assert!(default_labels
        .iter()
        .any(|label| label.contains("guava-user")));
    assert!(!default_labels
        .iter()
        .any(|label| label.starts_with("//external:")));
    assert!(!default_labels.iter().any(|label| {
        label.contains("bazel-diff-integration-lib")
            && !label.contains("libbazel-diff-integration-lib")
    }));
    assert!(impacted(
        second.path(),
        &from,
        &to,
        &opt_out,
        &["--no-excludeExternalTargets"],
    )
    .status
    .success());
    assert!(read_lines(&opt_out)
        .iter()
        .any(|label| label.starts_with("//external:")));
}

#[test]
fn transitive_external_repo_change_reaches_consumer() {
    if !supports_mod_show_repo() {
        return;
    }
    let first = copy_workspace("bzlmod_transitive_external");
    let second = copy_workspace("bzlmod_transitive_external");
    fs::write(second.path().join("inner/data.txt"), "world\n").unwrap();
    let impacted = diff_local(first.path(), second.path(), &[]);
    assert!(impacted.contains("//:consume") || impacted.contains("@@//:consume"));
}

/// cquery prints canonical labels (`@@inner+//:data`) where query prints apparent ones
/// (`@inner//:data`). The synthetic `//external:inner` node is named by the apparent name, so
/// until the canonical name was translated the edge from `@@outer+//:lib` to the node was dropped
/// and a change inside `inner` never reached `//:consume` under `--useCquery`. hashbench
/// (2026-10-18) hit the same gap on a rules_multitool lockfile bump.
#[test]
fn transitive_external_repo_change_reaches_consumer_cquery() {
    if !supports_mod_show_repo() {
        return;
    }
    let first = copy_workspace("bzlmod_transitive_external");
    let second = copy_workspace("bzlmod_transitive_external");
    fs::write(second.path().join("inner/data.txt"), "world\n").unwrap();
    let impacted = diff_local(first.path(), second.path(), &["--useCquery"]);
    assert!(
        impacted.contains("//:consume") || impacted.contains("@@//:consume"),
        "{impacted:?}"
    );
}

#[test]
fn remote_proto_bump_impacts_consumer() {
    let first = copy_workspace("proto_external_version_bump");
    let second = copy_workspace("proto_external_version_bump");
    edit(&second.path().join("MODULE.bazel"), |text| {
        text.replace(
            "bazel_dep(name = \"proto_dep\", version = \"1.0.0\")",
            "bazel_dep(name = \"proto_dep\", version = \"2.0.0\")",
        )
    });
    edit(&second.path().join("proto_dep/MODULE.bazel"), |text| {
        text.replace("version = \"1.0.0\"", "version = \"2.0.0\"")
    });
    edit(&second.path().join("proto_dep/greeting.proto"), |text| {
        text.replace(
            "message Greeting {\n  string message = 1;\n}",
            "message Greeting {\n  string message = 1;\n  string locale = 2;\n}",
        )
    });
    let impacted = diff_local(
        first.path(),
        second.path(),
        &["--fineGrainedHashExternalRepos", "@proto_dep"],
    );
    assert!(impacted.contains("//:consumer") || impacted.contains("@@//:consumer"));
    assert!(impacted
        .iter()
        .any(|label| label.ends_with("proto_dep//:greeting_java_proto")));
}

// Hub-and-spoke external repos -- e.g. rules_python's pip_parse in WORKSPACE mode, with a `@pip`
// hub of alias packages and one `@pip_<pkg>` spoke repo per package -- keep the change-detection
// signal in the spoke: bumping a pinned version rewrites the spoke repository rule's attrs, so only
// `//external:pip_numpy` flips. Users list the hub their BUILD files reference (`@pip`) rather than
// every generated spoke, and the consumer reaches the flipping seed through
// `@pip//numpy:pkg -> @pip_numpy//:lib -> //external:pip_numpy`. Fine-grained matching used to be an
// unbounded string prefix, so the spoke label looked like it belonged to the hub and was never
// rewritten to its seed, silently dropping consumers from the impacted set.
#[test]
fn hub_spoke_version_bump_impacts_consumer_behind_fine_grained_hub() {
    // WORKSPACE-only fixture: Bazel 9 dropped WORKSPACE, so `@pip` does not exist there at all.
    // The matching logic itself stays pinned on every version by the `hash` unit tests.
    if !supports_workspace() {
        return;
    }
    let first = copy_workspace("hub_spoke_external");
    let second = copy_workspace("hub_spoke_external");
    edit(&second.path().join("WORKSPACE"), |text| {
        text.replace("version = \"1.0\"", "version = \"2.0\"")
    });
    let impacted = diff_local(
        first.path(),
        second.path(),
        &["--fineGrainedHashExternalRepos", "@pip"],
    );
    // Sanity: if the spoke seed stops flipping the fixture no longer reproduces the signal and the
    // consumer assertion below proves nothing.
    assert!(impacted.contains("//external:pip_numpy"), "{impacted:?}");
    assert!(
        impacted.contains("//:consumer") || impacted.contains("@@//:consumer"),
        "{impacted:?}"
    );
}

#[test]
fn opaque_import_follows_the_used_hidden_alias_and_source() {
    if !supports_mod_show_repo() {
        return;
    }
    let workspace = copy_workspace("fine_grained_hub_by_canonical_name");
    let root = workspace.path();
    // Keep the imported hub's own RepoSpec fixed. A version changes only the
    // backing repository; its generated alias forwards to an ordinary filegroup.
    edit(&root.join("crates.bzl"), |source| {
        // The ordinary query can load this alias and genrule. Traversing its
        // opaque input would fetch an unrelated repository, which intentionally fails.
        let source = source.replace(
            "def _crates_impl(mctx):",
            "def _unavailable(rctx):\n    fail('unrelated_frontier_fetch')\n\nunavailable = repository_rule(implementation = _unavailable)\n\ndef _crates_impl(mctx):\n    unavailable(name = 'never_fetch')",
        ).replace(
            "        'exports_files",
            "        'alias(name = \"optional_tool\", actual = \":opaque\", visibility = [\"//visibility:public\"])',\n        'genrule(name = \"opaque\", srcs = [\"@never_fetch//:input\"], outs = [\"opaque.out\"], cmd = \"touch $@\")',\n        'exports_files",
        );
        source.replace("versions = json.encode(versions)", "versions = \"summary\"")
            .replace(
                "filegroup(name = \"data\",",
                "alias(name = \"data\", actual = \":payload\", visibility = [\"//visibility:public\"])\\nfilegroup(name = \"payload\",",
            )
    });
    edit(&root.join("BUILD.bazel"), |source| {
        format!("{source}\nfilegroup(name = \"optional\", srcs = [\"@crates//:optional_tool\"])\ngenrule(name = \"product\", srcs = [\":uses_a\", \":uses_b\"], outs = [\"product.txt\"], cmd = \"cat $(location :uses_a) $(location :uses_b) > $@\")\n")
    });
    let out = tempfile::tempdir().unwrap();
    let before = out.path().join("before.json");
    let after = out.path().join("after.json");
    let edges = out.path().join("edges.json");
    let result = out.path().join("changes.json");
    for (map, version) in [(&before, "1.0"), (&after, "2.0")] {
        fs::write(
            root.join("versions.json"),
            format!("{{\"a\": \"{version}\", \"b\": \"1.0\"}}\n"),
        )
        .unwrap();
        assert_product(root, "//:product", "product.txt", &format!("{version}1.0"));
        let generated = generate(root, map, &["--depEdgesFile", edges.to_str().unwrap()]);
        let stderr = String::from_utf8_lossy(&generated.stderr);
        assert!(!stderr.contains("unrelated_frontier_fetch"), "{stderr}");
        assert!(
            generated.status.success(),
            "{}",
            String::from_utf8_lossy(&generated.stderr)
        );
    }
    let generated = impacted(
        root,
        &before,
        &after,
        &result,
        &["--depEdgesFile", edges.to_str().unwrap()],
    );
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let changes: Vec<serde_json::Value> =
        serde_json::from_slice(&fs::read(&result).unwrap()).unwrap();
    let changed = |label: &str| changes.iter().any(|row| row["label"] == label);
    assert!(changed("//:uses_a") && changed("//:product"), "{changes:?}");
    assert!(
        !changed("//:uses_b") && !changed("//:uses_versions"),
        "{changes:?}"
    );
    let graph = dep_edges(&edges);
    let public = graph["//:uses_a"]
        .iter()
        .find(|name| name.ends_with("//:a"))
        .expect("actual imported alias");
    let hidden = graph[public]
        .iter()
        .find(|name| name.ends_with("crates__a//:data"))
        .expect("hidden alias");
    assert!(graph[hidden]
        .iter()
        .any(|label| label.ends_with("crates__a//:payload")));
    let base_hashes = hashes(&before);
    let head_hashes = hashes(&after);
    for (suffix, expected_change) in [
        ("crates__a//:data.txt", true),
        ("crates__b//:data.txt", false),
    ] {
        let (key, old) = base_hashes
            .iter()
            .find(|(key, _)| key.ends_with(suffix))
            .expect("external source");
        assert_eq!(
            head_hashes.get(key).unwrap().split_once('~').unwrap().1
                != old.split_once('~').unwrap().1,
            expected_change,
            "{key} direct digest"
        );
    }
}

// The Bzlmod form of the earlier pip case names the fine hub canonically while `query` prints the
// apparent `@crates//:a`. Resolve that enrollment so each crate keeps its own inputs. The hub's
// `versions.txt`, also named by its apparent label, must be hashed by content under either name.
#[test]
fn hub_named_by_canonical_name_is_fine_grained_under_its_apparent_name() {
    if !supports_mod_show_repo() {
        return;
    }
    let first = copy_workspace("fine_grained_hub_by_canonical_name");
    let second = copy_workspace("fine_grained_hub_by_canonical_name");
    edit(&second.path().join("versions.json"), |text| {
        text.replace("\"a\": \"1.0\"", "\"a\": \"2.0\"")
    });
    for repo in ["@crates", "@@+crates+crates"] {
        let impacted = diff_local(
            first.path(),
            second.path(),
            &["--fineGrainedHashExternalRepos", repo],
        );
        let main: BTreeSet<_> = impacted
            .iter()
            .filter(|label| !label.starts_with("//external:") && !label.starts_with("@@crates"))
            .map(|label| label.trim_start_matches("@@").to_owned())
            .filter(|label| label.starts_with("//"))
            .collect();
        assert_eq!(
            main,
            BTreeSet::from(["//:uses_a".to_owned(), "//:uses_versions".to_owned()]),
            "{repo}: {impacted:?}"
        );
    }
}

// Module `ext`'s extension generates the `@crates` hub and its spokes, whose targets use a rule
// `ext` defines. In query mode `//external:ext` stands in for everything its extensions generate,
// so a fine-grained spoke target reaching `ext` through it changes whenever any other spoke does.
// With the extension listed in `--labelOnlyModuleExtensions`, bumping spoke `b` impacts only
// `//:uses_b`, while a change to `ext` itself still impacts both consumers. Without it, the
// conservative edge stays and the bump impacts both.
#[test]
fn fine_grained_spoke_does_not_reach_its_siblings_through_the_owning_module() {
    if !supports_mod_show_repo() {
        return;
    }
    let fine_grained = [
        "--fineGrainedHashExternalRepos",
        "@crates,@@ext++crates+crates__a",
        "--labelOnlyModuleExtensions",
        "@ext//:crates.bzl%crates",
    ];
    let main = |impacted: BTreeSet<String>| -> BTreeSet<String> {
        impacted
            .into_iter()
            .map(|label| label.trim_start_matches("@@").to_owned())
            .filter(|label| label.starts_with("//") && !label.starts_with("//external:"))
            .collect()
    };
    let first = copy_workspace("extension_spokes_through_owner");
    let bumped = copy_workspace("extension_spokes_through_owner");
    edit(&bumped.path().join("versions.json"), |text| {
        text.replace("\"b\": \"1.0\"", "\"b\": \"2.0\"")
    });
    let impacted = main(diff_local(first.path(), bumped.path(), &fine_grained));
    assert_eq!(impacted, BTreeSet::from(["//:uses_b".to_owned()]));
    let impacted = main(diff_local(first.path(), bumped.path(), &fine_grained[..2]));
    assert_eq!(
        impacted,
        BTreeSet::from(["//:uses_a".to_owned(), "//:uses_b".to_owned()])
    );

    let changed_rule = copy_workspace("extension_spokes_through_owner");
    fs::write(changed_rule.path().join("ext/tool.sh"), "exit 1\n").unwrap();
    let impacted = main(diff_local(first.path(), changed_rule.path(), &fine_grained));
    assert_eq!(
        impacted,
        BTreeSet::from(["//:uses_a".to_owned(), "//:uses_b".to_owned()])
    );
}

// Issue #603. Module `ext` owns the `@crates` extension, whose spokes are named after their
// version the way rules_js's `npm` names `npm__user-agents__2.1.229`, so a bump replaces spoke `b`
// rather than changing it. In query mode `//external:ext` depends on every repository its
// extensions generate, so the bump reaches every target that uses `ext`'s own rule (`//:uses_ext`,
// like a js_binary) and every target of a module with a `bazel_dep` path to `ext`
// (`//:uses_dependent`, whose `dependent` reaches `ext` through `middle`, like rules_jest reaching
// gazelle). Neither names anything in `@crates`. With the extension listed in
// `--labelOnlyModuleExtensions`, `ext` no longer stands in for its repositories, so the bump
// impacts only the hub's consumers, with or without fine-graining; a change to `ext` itself must
// still reach both.
#[test]
fn label_only_extension_bump_does_not_reach_users_of_the_owner_or_its_dependents() {
    if !supports_mod_show_repo() {
        return;
    }
    let label_only = ["--labelOnlyModuleExtensions", "@ext//:crates.bzl%crates"];
    let fine_grained = [
        label_only[0],
        label_only[1],
        "--fineGrainedHashExternalRepos",
        "@crates",
    ];
    let main = |impacted: BTreeSet<String>| -> BTreeSet<String> {
        impacted
            .into_iter()
            .map(|label| label.trim_start_matches("@@").to_owned())
            .filter(|label| label.starts_with("//") && !label.starts_with("//external:"))
            .collect()
    };
    let set = |labels: &[&str]| -> BTreeSet<String> {
        labels.iter().map(|label| label.to_string()).collect()
    };
    let first = copy_workspace("extension_owner_dependent_module");
    let bumped = copy_workspace("extension_owner_dependent_module");
    edit(&bumped.path().join("versions.json"), |text| {
        text.replace("\"b\": \"1.0\"", "\"b\": \"2.0\"")
    });
    // Without the opt-in the conservative owner edge stays and the bump reaches both, which is
    // what the issue reports.
    let impacted = main(diff_local(first.path(), bumped.path(), &[]));
    assert!(
        impacted.contains("//:uses_ext") && impacted.contains("//:uses_dependent"),
        "{impacted:?}"
    );

    // Without fine-graining every consumer of the `@crates` hub sees the bump.
    let impacted = main(diff_local(first.path(), bumped.path(), &label_only));
    assert_eq!(impacted, set(&["//:uses_a", "//:uses_b"]), "label-only");
    let impacted = main(diff_local(first.path(), bumped.path(), &fine_grained));
    assert_eq!(impacted, set(&["//:uses_b"]), "label-only, fine-grained");

    // `dependent` and `//:uses_ext` really depend on `ext`: a change to its own tree reaches them.
    let changed_owner = copy_workspace("extension_owner_dependent_module");
    fs::write(changed_owner.path().join("ext/tool.sh"), "exit 1\n").unwrap();
    for flags in [&label_only[..], &fine_grained[..]] {
        let impacted = main(diff_local(first.path(), changed_owner.path(), flags));
        assert!(
            impacted.contains("//:uses_ext") && impacted.contains("//:uses_dependent"),
            "{flags:?}: {impacted:?}"
        );
    }
}

#[test]
fn fine_aliases_acquire_hidden_libraries_and_definition_sources() {
    if !supports_mod_show_repo() {
        return;
    }
    fn external_key<V>(map: &std::collections::BTreeMap<String, V>, suffix: &str) -> String {
        let keys = map
            .keys()
            .filter(|key| key.starts_with('@') && key.ends_with(suffix))
            .collect::<Vec<_>>();
        assert_eq!(keys.len(), 1, "expected one {suffix}: {keys:?}");
        keys[0].as_str().to_owned()
    }
    fn direct(hash: &str) -> &str {
        hash.rsplit_once('~').unwrap().1
    }

    let workspace = copy_workspace("fine_alias_acquisition");
    let root = workspace.path();
    let out = tempfile::tempdir().unwrap();
    let build_path = root.join("library/BUILD.bazel");
    let build = fs::read_to_string(&build_path).unwrap();
    let implementation_path = root.join("library/defs/library.bzl");
    let implementation = fs::read_to_string(&implementation_path).unwrap();
    let unrelated_path = root.join("unrelated/rules.bzl");
    let unrelated = fs::read_to_string(&unrelated_path).unwrap();
    let modes: [(&str, &[&str]); 2] = [
        ("fine", &["--fineGrainedHashExternalRepos=@public"]),
        (
            "excluded",
            &[
                "--fineGrainedHashExternalRepos=@public",
                "--excludeExternalTargets",
            ],
        ),
    ];
    let mut snapshots = std::collections::BTreeMap::new();
    for (state, data, other, unrelated_edit, product) in [
        ("base", "before\n", false, false, "before"),
        ("source", "after\n", false, false, "after"),
        ("definition", "before\n", true, false, "other"),
        ("implementation", "before\n", false, false, "other"),
        ("unrelated", "before\n", false, true, "before"),
    ] {
        fs::write(root.join("library/data.txt"), data).unwrap();
        fs::write(
            &build_path,
            if other {
                build.replace("selected = \"data.txt\"", "selected = \"other.txt\"")
            } else {
                build.clone()
            },
        )
        .unwrap();
        fs::write(
            &implementation_path,
            if state == "implementation" {
                implementation.replace(
                    "file.basename == ctx.attr.selected",
                    "file.basename != ctx.attr.selected",
                )
            } else {
                implementation.clone()
            },
        )
        .unwrap();
        fs::write(
            &unrelated_path,
            format!(
                "{unrelated}{}",
                if unrelated_edit {
                    "\n# unrelated edit\n"
                } else {
                    ""
                }
            ),
        )
        .unwrap();
        assert_product(root, "//:consumer", "consumer.txt", product);
        for (mode, flags) in modes {
            let hashes = out.path().join(format!("{state}-{mode}.json"));
            let edges = out.path().join(format!("{state}-{mode}-edges.json"));
            let mut args = flags.to_vec();
            args.extend(["--includeTargetType", "-d", edges.to_str().unwrap()]);
            let generated = generate(root, &hashes, &args);
            assert!(
                generated.status.success(),
                "{state} {mode}: {}",
                String::from_utf8_lossy(&generated.stderr)
            );
            snapshots.insert((state, mode), (hashes, edges));
        }
    }
    for (mode, _) in modes {
        for (state, expected) in [
            ("source", true),
            ("definition", true),
            ("implementation", true),
            ("unrelated", false),
        ] {
            let result = out.path().join(format!("{state}-{mode}-impact.txt"));
            let impact = impacted(
                root,
                &snapshots[&("base", mode)].0,
                &snapshots[&(state, mode)].0,
                &result,
                &[],
            );
            assert!(
                impact.status.success(),
                "{state} {mode}: {}",
                String::from_utf8_lossy(&impact.stderr)
            );
            let selected = read_lines(&result);
            assert_eq!(
                selected.contains("//:consumer"),
                expected,
                "{state} {mode}: {selected:?}"
            );
            if state == "unrelated" {
                assert!(selected.contains("//unrelated:probe"));
            }
        }
        let base = hashes(&snapshots[&("base", mode)].0);
        let source = hashes(&snapshots[&("source", mode)].0);
        let definition = hashes(&snapshots[&("definition", mode)].0);
        let data = external_key(&base, "library//:data.txt");
        let other = external_key(&base, "library//:other.txt");
        let build = external_key(&base, "library//:BUILD.bazel");
        let library_hash = external_key(&base, "library//:lib");
        assert_ne!(direct(&base[&data]), direct(&source[&data]));
        assert_ne!(direct(&base[&library_hash]), direct(&source[&library_hash]));
        assert_eq!(direct(&base[&other]), direct(&source[&other]));
        assert_eq!(direct(&base[&build]), direct(&source[&build]));
        assert_ne!(direct(&base[&build]), direct(&definition[&build]));
        assert_eq!(direct(&base[&data]), direct(&definition[&data]));

        let implementation = hashes(&snapshots[&("implementation", mode)].0);
        let bzl = external_key(&base, "library//defs:library.bzl");
        assert_ne!(direct(&base[&bzl]), direct(&implementation[&bzl]));
        for file in [&build, &data, &other] {
            assert_eq!(direct(&base[file]), direct(&implementation[file]));
        }

        let edges = dep_edges(&snapshots[&("base", mode)].1);
        let public = external_key(&edges, "public//:forward");
        let hidden = external_key(&edges, "hidden//:forward");
        let library = external_key(&edges, "library//:lib");
        assert!(edges["//:consumer"].contains(&public));
        assert!(edges[&public].contains(&hidden));
        assert!(edges[&hidden].contains(&library));
        external_key(&base, "hidden//:BUILD.bazel");
    }
}

#[test]
fn ordinary_filegroup_honors_an_ignored_output_group() {
    if !supports_mod_show_repo() {
        return;
    }
    let workspace = copy_workspace("cross_extension_toolchain");
    let root = workspace.path();
    let out = tempfile::tempdir().unwrap();
    let build = root.join("BUILD.bazel");
    let original = fs::read_to_string(&build).unwrap();
    let mut direct = [Vec::new(), Vec::new()];
    let mut inputs = None;
    for (arm, group, product) in [("before", "", "A"), ("after", "absent_group", "")] {
        fs::write(
            &build,
            format!(
                r#"{original}
filegroup(name = "files", srcs = ["@assets//:neighbor"], output_group = "{group}")
genrule(
    name = "output_product",
    srcs = [":files"],
    outs = ["group.txt"],
    cmd = "for f in $(SRCS); do cat \"$$f\"; done > $@",
)
"#
            ),
        )
        .unwrap();
        assert_product(root, "//:output_product", "group.txt", product);
        for (index, profile) in ["tracked", "ignored"].into_iter().enumerate() {
            let map = out.path().join(format!("{arm}-{profile}"));
            let edges = map.with_extension("edges");
            let mut args = vec!["--bazelCommandOptions=--proto:output_rule_attrs=tags --noproto:include_synthetic_attribute_hash", "--depEdgesFile", edges.to_str().unwrap()];
            if profile == "ignored" {
                args.push("--ignoredRuleHashingAttributes=output_group");
            }
            let result = generate(root, &map, &args);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let graph = dep_edges(&edges);
            let observed = &graph["//:files"];
            assert!(observed.contains("@assets//:neighbor"));
            assert_eq!(inputs.get_or_insert_with(|| observed.clone()), observed);
            direct[index].push(
                hashes(&map)["//:files"]
                    .rsplit_once('~')
                    .unwrap()
                    .1
                    .to_owned(),
            );
        }
    }
    assert_ne!(direct[0][0], direct[0][1]);
    assert_eq!(direct[1][0], direct[1][1]);
}

#[test]
fn fine_aliases_track_the_selected_destination_with_fixed_inputs() {
    if !supports_mod_show_repo() {
        return;
    }
    let workspace = copy_workspace("fine_alias_acquisition");
    let root = workspace.path();
    let output = tempfile::tempdir().unwrap();
    edit(&root.join("library/BUILD.bazel"), |text| {
        format!("{text}\nexports_files([\"other.txt\"])\n")
    });
    edit(&root.join("MODULE.bazel"), |text| {
        text.replace(
            r#"use_repo(aliases, "public")"#,
            r#"use_repo(aliases, "public", "hidden")"#,
        )
    });
    let mut snapshots = [Vec::new(), Vec::new()];
    let first = "@hidden//:forward";
    let other = "@library//:other.txt";
    for (name, default, alternate, sibling, product) in [
        ("base", first, other, first, "before"),
        ("sibling", first, other, other, "before"),
        ("swapped", other, first, other, "other"),
    ] {
        fs::write(
            root.join("public.BUILD"),
            format!(
                r#"config_setting(name = "alt", values = {{"define": "choice=alt"}})
alias(
    name = "forward",
    actual = select({{":alt": "{alternate}", "//conditions:default": "{default}"}}),
    visibility = ["//visibility:public"],
)
alias(name = "sibling", actual = "{sibling}")
"#
            ),
        )
        .unwrap();
        assert_product(root, "//:consumer", "consumer.txt", product);
        for (idx, fine) in ["@public", "@public,@hidden,@library"]
            .into_iter()
            .enumerate()
        {
            let out = output.path().join(format!("{name}-{idx}.json"));
            let edges = output.path().join(format!("{name}-{idx}-edges.json"));
            let generated = generate(
                root,
                &out,
                &[
                    &format!("--fineGrainedHashExternalRepos={fine}"),
                    "--bazelCommandOptions=--proto:output_rule_attrs=tags",
                    "-d",
                    edges.to_str().unwrap(),
                ],
            );
            assert!(
                generated.status.success(),
                "{}",
                String::from_utf8_lossy(&generated.stderr)
            );
            let graph = dep_edges(&edges);
            let key = graph
                .keys()
                .find(|k| k.ends_with("public//:forward"))
                .unwrap();
            snapshots[idx].push((hashes(&out)[key].clone(), graph[key].clone(), out));
        }
    }
    for (idx, profile) in snapshots.into_iter().enumerate() {
        let [(before, inputs, first), (unchanged, sibling_inputs, _), (after, swapped_inputs, second)] =
            profile.as_slice()
        else {
            unreachable!()
        };
        assert_eq!(inputs, sibling_inputs);
        assert_eq!(inputs, swapped_inputs);
        assert_eq!(before.rsplit('~').next(), unchanged.rsplit('~').next());
        assert_ne!(
            before.rsplit('~').next(),
            after.rsplit('~').next(),
            "fine profile {idx}"
        );
        let out = output.path().join("impact.txt");
        assert!(impacted(root, first, second, &out, &[]).status.success());
        assert!(read_lines(&out).contains("//:consumer"));
    }
}

#[test]
fn fine_aliases_preserve_partial_rebuilds() {
    if !supports_mod_show_repo() {
        return;
    }
    let workspace = copy_workspace("fine_alias_acquisition");
    let root = workspace.path();
    assert_product(root, "//:consumer", "consumer.txt", "before");
    init_git(root);
    let out = tempfile::tempdir().unwrap();
    let partial = |name: &str, base: Option<&std::path::Path>| {
        let hashes = out.path().join(format!("{name}.json"));
        let edges = out.path().join(format!("{name}-edges.json"));
        let edge_arg = edges.display().to_string();
        let base_arg = base.map(|path| path.display().to_string());
        let mut args = vec![
            "--fineGrainedHashExternalRepos=@public",
            "--excludeExternalTargets",
            "--partialGraph",
            "-d",
            &edge_arg,
        ];
        if let Some(base) = &base_arg {
            args.extend(["--baseHashes", base]);
        }
        let result = generate(root, &hashes, &args);
        let log = String::from_utf8_lossy(&result.stderr).into_owned();
        assert!(result.status.success(), "{name}: {log}");
        (hashes, edges, log)
    };
    partial("warm", None);
    if !git(root, &["status", "--porcelain"]).is_empty() {
        commit(root, "settle repository metadata");
    }
    let lock_path = root.join("MODULE.bazel.lock");
    let lock = fs::read(&lock_path).unwrap();
    let (base, _, _) = partial("base", None);
    assert_eq!(fs::read(&lock_path).unwrap(), lock);
    fs::write(root.join("library/data.txt"), "after\n").unwrap();
    assert_product(root, "//:consumer", "consumer.txt", "after");
    assert_eq!(fs::read(&lock_path).unwrap(), lock);
    assert_eq!(git(root, &["diff", "--name-only"]), "library/data.txt");
    assert!(git(root, &["ls-files", "--others", "--exclude-standard"]).is_empty());
    let (reused, reused_edges, log) = partial("reused", Some(&base));
    assert!(
        log.contains("full generation")
            && log.contains("read while loading")
            && log.contains("library"),
        "{log}"
    );
    let (fresh, fresh_edges, _) = partial("fresh", None);
    assert_eq!(fs::read(&reused).unwrap(), fs::read(&fresh).unwrap());
    assert_eq!(dep_edges(&reused_edges), dep_edges(&fresh_edges));
    assert!(dep_edges(&fresh_edges).iter().any(|(label, inputs)| {
        label.ends_with("hidden//:forward")
            && inputs.iter().any(|input| input.ends_with("library//:lib"))
    }));
    let selected = out.path().join("selected.txt");
    let result = impacted(root, &base, &reused, &selected, &[]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(read_lines(&selected).contains("//:consumer"));
}

#[test]
fn fine_aliases_honor_query_failure_mode() {
    if !supports_mod_show_repo() {
        return;
    }
    let workspace = copy_workspace("fine_alias_acquisition");
    let root = workspace.path();
    edit(&root.join("public.BUILD"), |text| {
        format!("{text}\nalias(name = \"dangling\", actual = \"@hidden//:missing\")\n")
    });
    edit(&root.join("BUILD.bazel"), |text| {
        format!("{text}\nfilegroup(name = \"uses_dangling\", srcs = [\"@public//:dangling\"])\n")
    });
    let out = tempfile::tempdir().unwrap();
    let strict = out.path().join("strict.json");
    let flags = [
        "--fineGrainedHashExternalRepos=@public",
        "--excludeExternalTargets",
    ];
    let result = generate(root, &strict, &flags);
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "{error}");
    assert!(
        error.contains("failed to acquire ordinary alias inputs") && error.contains("//:missing"),
        "{error}"
    );
    assert!(!strict.exists());

    let kept = out.path().join("kept.json");
    let edges = out.path().join("kept-edges.json");
    let mut args = flags.to_vec();
    args.extend(["--keep_going", "-d", edges.to_str().unwrap()]);
    let result = generate(root, &kept, &args);
    let warning = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "{warning}");
    assert!(
        warning.contains("keeping ordinary repository fallbacks for incomplete alias discovery"),
        "{warning}"
    );
    assert!(!dep_edges(&edges)
        .keys()
        .any(|label| label.ends_with("hidden//:forward")));
}

const ISOLATED_ROOT: &[&str] = &["--isolatedDependencyRoot", "@hub"];

fn assert_product(workspace: &std::path::Path, target: &str, file: &str, expected: &str) {
    let build = std::process::Command::new(bazel())
        .current_dir(workspace)
        .args(["build", target])
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    assert_eq!(
        fs::read_to_string(workspace.join("bazel-bin").join(file))
            .unwrap()
            .trim(),
        expected
    );
}

#[test]
fn isolated_dependency_root_reaches_alias_direct_and_build_load_readers() {
    if !supports_mod_show_repo() {
        return;
    }
    let base = copy_workspace("isolated_dependency_root");
    let head = copy_workspace("isolated_dependency_root");
    edit(&head.path().join("settings.json"), |s| {
        s.replace("before", "after")
    });
    assert!(diff_local(base.path(), head.path(), &[]).contains("//outside:uses_owner"));
    let changed = diff_local(base.path(), head.path(), ISOLATED_ROOT);
    for reader in ["//:alias", "//:direct", "//:loaded"] {
        assert!(changed.contains(reader), "missing {reader}: {changed:?}");
    }
    assert!(!changed.contains("//outside:uses_owner"), "{changed:?}");
    assert_product(base.path(), "//:direct", "direct.txt", "before");
    assert_product(head.path(), "//:direct", "direct.txt", "after");

    let comment = copy_workspace("isolated_dependency_root");
    edit(&comment.path().join("settings.json"), |s| {
        s.replace("before", "before-comment")
    });
    let maps = tempfile::tempdir().unwrap();
    let direct = |ws: &std::path::Path, name: &str| {
        let map = maps.path().join(name);
        assert!(generate(ws, &map, ISOLATED_ROOT).status.success());
        let data = hashes(&map);
        (
            data["@hub//:defs.bzl"].clone(),
            data["//external:hub"].split_once('~').unwrap().1.to_owned(),
        )
    };
    let before = direct(base.path(), "base.json");
    let after = direct(comment.path(), "comment.json");
    let captured: serde_json::Value =
        serde_json::from_slice(&fs::read(maps.path().join("base.json")).unwrap()).unwrap();
    let graph: serde_json::Value =
        serde_json::from_str(captured["metadata"]["moduleGraphJson"].as_str().unwrap()).unwrap();
    assert_eq!(graph["key"], "<root>");
    assert!(
        graph["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|module| module["dependencies"].as_array().is_some_and(Vec::is_empty)),
        "{graph}"
    );
    assert_ne!(before.0, after.0);
    assert_ne!(before.1, after.1);
    assert_product(comment.path(), "//:direct", "direct.txt", "before");

    edit(&base.path().join("MODULE.bazel"), |module| {
        module.replace(
            "use_repo(family, \"hub\")",
            "use_repo(family, \"hub\", \"app\")",
        )
    });
    let refused = maps.path().join("refused.json");
    let output = generate(base.path(), &refused, ISOLATED_ROOT);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("--isolatedDependencyRoot=@hub")
            && stderr.contains("extra imported repository")
            && stderr.contains("+app"),
        "{stderr}"
    );
    assert!(!refused.exists(), "failed admission wrote a hash file");
    let unflagged = maps.path().join("unflagged.json");
    let output = generate(base.path(), &unflagged, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(hashes(&unflagged).contains_key("//:direct"));
}

#[test]
fn isolated_dependency_root_tracks_repository_read_bytes() {
    if !supports_mod_show_repo() {
        return;
    }
    let base = copy_workspace("isolated_dependency_root");
    for (input, contents, target, product, initial, expected) in [
        (
            "registry.txt",
            "changed",
            "//:reads_registry",
            "registry-output.txt",
            "original",
            "changed",
        ),
        (
            "alias.txt",
            "changed",
            "//:reads_alias",
            "alias-output.txt",
            "absent",
            "changed",
        ),
        // No queried output changes. Only the typed repository input changes
        // from absent to present at the alias's path.
        (
            "alias.txt",
            "absent\nnew file",
            "//:reads_alias",
            "alias-output.txt",
            "absent",
            "absent",
        ),
    ] {
        let head = copy_workspace("isolated_dependency_root");
        fs::write(head.path().join(input), contents).unwrap();
        let changed = diff_local(base.path(), head.path(), ISOLATED_ROOT);
        assert!(changed.contains(target), "{input}: {changed:?}");
        assert!(
            !changed.contains("//outside:uses_owner"),
            "{input}: {changed:?}"
        );
        assert_product(base.path(), target, product, initial);
        assert_product(head.path(), target, product, expected);
    }
}

#[test]
fn isolated_dependency_root_keeps_hidden_spoke_changes() {
    if !supports_mod_show_repo() {
        return;
    }
    let base = copy_workspace("isolated_dependency_root");
    let head = copy_workspace("isolated_dependency_root");
    edit(&head.path().join("settings.json"), |s| {
        s.replace("\"1\"", "\"2\"")
    });
    let changed = diff_local(base.path(), head.path(), ISOLATED_ROOT);
    assert!(
        changed.contains("//:alias") && changed.contains("//:direct"),
        "{changed:?}"
    );
    assert!(!changed.contains("//outside:uses_owner"), "{changed:?}");
}

#[test]
fn two_typed_spokes_keep_independent_partial_impacts() {
    if !supports_mod_show_repo() {
        return;
    }
    let workspace = copy_workspace("extension_spokes_through_owner");
    let root = workspace.path();
    let precise = supports_static_toolchain_metadata(root);
    edit(&root.join("ext/MODULE.bazel"), |module| {
        format!("{module}\nuse_repo(crates, \"sdk_provider\")\nregister_toolchains(\"@sdk_provider//:registration\")\n")
    });
    edit(&root.join("BUILD.bazel"), |build| {
        format!(
            r#"{build}
genrule(
    name = "products",
    srcs = [":uses_a", ":uses_b"],
    outs = ["products.txt"],
    cmd = "(cat $(location :uses_a); echo; cat $(location :uses_b)) > $@",
)
"#
        )
    });

    let out = tempfile::tempdir().unwrap();
    let mut saved_sources = Vec::new();
    for (arm, b, sdk) in [("base", "1", "1"), ("b", "2", "1"), ("sdk", "1", "2")] {
        fs::write(
            root.join("versions.json"),
            format!(r#"{{"a":"1","b":"{b}","sdk":"{sdk}"}}"#),
        )
        .unwrap();
        assert_product(
            root,
            "//:products",
            "products.txt",
            &format!("1|{sdk}\n{b}|{sdk}"),
        );
        if arm == "base" {
            init_git(root);
        }
        for (mode, partial) in [("full", false), ("partial", true)] {
            let map = out.path().join(format!("{mode}-{arm}"));
            let edges = out.path().join(format!("{mode}-{arm}-edges"));
            let mut flags = vec![
                "--fineGrainedHashExternalRepos", "@crates", "--excludeExternalTargets",
                "--bazelCommandOptions=--proto:output_rule_attrs=tags --proto:include_synthetic_attribute_hash",
                "-d", edges.to_str().unwrap(),
            ];
            if partial {
                flags.push("--partialGraph");
            }
            let result = generate(root, &map, &flags);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let base = out.path().join(format!("{mode}-base"));
            if partial {
                let doc: serde_json::Value =
                    serde_json::from_slice(&fs::read(&map).unwrap()).unwrap();
                let sources = &doc["metadata"]["partialGraph"]["externalSources"];
                saved_sources.push(["a", "b"].map(|spoke| {
                    let file = format!("@@ext++crates+crates__{spoke}//:data.txt");
                    sources[&file]
                        .as_str()
                        .expect("returned spoke source")
                        .to_owned()
                }));
                if arm != "base" {
                    let reused = out.path().join("reused");
                    let fresh_edges = dep_edges(&edges);
                    flags.extend(["--baseHashes", base.to_str().unwrap()]);
                    let result = generate(root, &reused, &flags);
                    assert!(
                        result.status.success(),
                        "{}",
                        String::from_utf8_lossy(&result.stderr)
                    );
                    assert_eq!(fs::read(&map).unwrap(), fs::read(reused).unwrap());
                    assert_eq!(fresh_edges, dep_edges(&edges));
                }
            }
            if arm != "base" {
                let output = out.path().join("impact");
                let result = impacted(root, &base, &map, &output, &[]);
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let labels = read_lines(&output);
                let has = |target| {
                    labels
                        .iter()
                        .any(|label| label.trim_start_matches('@') == target)
                };
                assert!(has("//:uses_b"), "{mode} {arm}: {labels:?}");
                if arm == "sdk" || precise {
                    assert_eq!(has("//:uses_a"), arm == "sdk", "{mode} {arm}: {labels:?}");
                }
            }
        }
    }
    assert_eq!(saved_sources[0][0], saved_sources[1][0]);
    assert_ne!(saved_sources[0][1], saved_sources[1][1]);
    assert_eq!(saved_sources[0], saved_sources[2]);
}

fn workspace_output(root: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new(bazel())
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn transition_registration_alias_only_reaches_matching_readers() {
    let workspace = copy_workspace("transition_registration_holder");
    let root = workspace.path();
    if !supports_static_toolchain_metadata(root) {
        return;
    }
    // The primary tool is available only through a transition, and every
    // ordinary attribute names its alias instead of the declaration itself.
    edit(&root.join("MODULE.bazel"), |s| {
        s.replace(", \"//:available\"", "")
    });
    edit(&root.join("BUILD.bazel"), |s| {
        let build = s.replace(
            "registration = \":available\"",
            "registration = \":available_ref\"",
        );
        format!(
            r#"load(":defs.bzl", "forward")
{build}
alias(name = "available_ref", actual = ":available")
ordinary_reader(name = "inner")
forward(name = "outer", child = ":inner", registration = ":available_ref")
"#
        )
    });
    fs::write(root.join("other.txt"), "stable").unwrap();
    let out = tempfile::tempdir().unwrap();
    for value in ["one", "two"] {
        fs::write(root.join("primary.txt"), value).unwrap();
        workspace_output(
            root,
            &[
                "build",
                "//:explicit",
                "//:outer",
                "//:holder",
                "//:default_reader",
            ],
        );
        let files = workspace_output(
            root,
            &[
                "cquery",
                "set(//:explicit //:outer //:holder //:default_reader)",
                "--output=files",
            ],
        );
        let products: std::collections::BTreeMap<_, _> = files
            .lines()
            .map(|file| {
                let path = std::path::Path::new(file);
                (
                    path.file_stem().unwrap().to_str().unwrap(),
                    fs::read_to_string(root.join(path)).unwrap(),
                )
            })
            .collect();
        for reader in ["explicit", "outer"] {
            assert_eq!(products[reader], value);
        }
        assert_eq!(products["default_reader"].trim_end(), "fallback");
        assert!(products["holder"].ends_with("//:primary"));
        let hashes = out.path().join(value);
        let result = generate(root, &hashes, &[]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let output = out.path().join("impact");
    let result = impacted(
        root,
        &out.path().join("one"),
        &out.path().join("two"),
        &output,
        &[],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let changed = read_lines(&output);
    for reader in ["//:explicit", "//:outer"] {
        assert!(
            changed
                .iter()
                .any(|label| label.trim_start_matches('@') == reader),
            "{changed:?}"
        );
    }
    for ordinary in ["//:holder", "//:default_reader"] {
        assert!(
            !changed
                .iter()
                .any(|label| label.trim_start_matches('@') == ordinary),
            "{changed:?}"
        );
    }
}

#[test]
fn transition_registration_holder_depends_on_the_binding() {
    if !supports_mod_show_repo() {
        return;
    }
    let workspace = copy_workspace("transition_registration_holder");
    let root = workspace.path();
    let bazel_output = |args: &[&str]| workspace_output(root, args);
    let typed = supports_static_toolchain_metadata(root);
    let out = tempfile::tempdir().unwrap();
    let template = fs::read_to_string(root.join("BUILD.bazel")).unwrap();
    let generate_map = |name: &str, partial: bool, base: Option<&std::path::Path>| {
        let hashes = out.path().join(name);
        let edges = out.path().join(format!("{name}-edges.json"));
        let mut args = vec!["-d", edges.to_str().unwrap()];
        if partial {
            args.push("--partialGraph");
        }
        if let Some(base) = base {
            args.extend(["--baseHashes", base.to_str().unwrap()]);
        }
        let result = generate(root, &hashes, &args);
        let log = String::from_utf8_lossy(&result.stderr).into_owned();
        assert!(result.status.success(), "{name}: {log}");
        (hashes, edges, log)
    };
    let distances = |before: &std::path::Path, after: &std::path::Path, edges: &std::path::Path| {
        let output = out.path().join("impact.json");
        let result = impacted(
            root,
            before,
            after,
            &output,
            &["-d", edges.to_str().unwrap()],
        );
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let impact: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        [
            "//:holder",
            "//:reader",
            "//:available",
            "//:explicit",
            "//:default_reader",
        ]
        .map(|label| {
            impact
                .iter()
                .find(|row| row["label"] == label)
                .and_then(|row| row["targetDistance"].as_u64())
        })
    };
    let targets = "set(//:holder //:reader //:default_reader //:explicit)";
    let mut actual = Vec::new();
    let mut base_lock = None;
    for (name, body, binding, other) in [
        ("base", "one", "primary", "base"),
        ("impl", "two", "primary", "base"),
        ("binding", "one", "spare", "base"),
        ("ordinary", "one", "primary", "mixed"),
        ("both", "two", "primary", "mixed"),
    ] {
        fs::write(root.join("primary.txt"), body).unwrap();
        fs::write(root.join("other.txt"), other).unwrap();
        fs::write(
            root.join("BUILD.bazel"),
            template.replace(
                "toolchain = \":primary\"",
                &format!("toolchain = \":{binding}\""),
            ),
        )
        .unwrap();
        bazel_output(&[
            "build",
            "//:holder",
            "//:reader",
            "//:default_reader",
            "//:explicit",
        ]);
        let files = bazel_output(&["cquery", targets, "--output=files"]);
        let products: std::collections::BTreeMap<_, _> = files
            .lines()
            .map(|file| {
                let path = std::path::Path::new(file);
                (
                    path.file_stem().unwrap().to_str().unwrap(),
                    fs::read_to_string(root.join(path)).unwrap(),
                )
            })
            .collect();
        assert_eq!(
            products["holder"].trim_start_matches('@'),
            format!("//:{binding}")
        );
        let expected = if binding == "spare" { "spare" } else { body };
        assert_eq!(products["reader"].trim_end(), expected);
        assert_eq!(products["explicit"].trim_end(), expected);
        assert_eq!(products["default_reader"].trim_end(), "fallback");
        assert_eq!(products["other"], other);

        let (full, edges, _) = generate_map(name, false, None);
        if name == "base" {
            init_git(root);
            generate_map("warm", true, None);
            if !git(root, &["status", "--porcelain"]).is_empty() {
                commit(root, "settle repository metadata");
            }
            base_lock = Some(fs::read(root.join("MODULE.bazel.lock")).unwrap());
        }
        let (fresh, fresh_edges, _) = generate_map(&format!("partial-{name}"), true, None);
        assert_eq!(
            Some(fs::read(root.join("MODULE.bazel.lock")).unwrap()),
            base_lock
        );
        if name == "base" {
            let document: serde_json::Value =
                serde_json::from_slice(&fs::read(&fresh).unwrap()).unwrap();
            assert_eq!(
                document["metadata"]["partialGraph"]["directToolchainInputs"],
                typed
            );
            let absent_bazel = out.path().join("absent-bazel");
            let offline = out.path().join("offline");
            let result = run([
                "generate-hashes",
                "-w",
                root.to_str().unwrap(),
                "-b",
                absent_bazel.to_str().unwrap(),
                "--partialGraph",
                "--baseHashes",
                fresh.to_str().unwrap(),
                "-d",
                out.path().join("offline-edges.json").to_str().unwrap(),
                offline.to_str().unwrap(),
            ]);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(fs::read(offline).unwrap(), fs::read(&fresh).unwrap());
            continue;
        }
        let base = out.path().join("partial-base");
        let (reused, reused_edges, log) = generate_map("reused", true, Some(&base));
        if name == "binding" {
            assert!(
                log.contains("full generation") && log.contains("BUILD.bazel"),
                "{log}"
            );
        } else {
            assert!(!log.contains("full generation"), "{log}");
        }
        assert_eq!(fs::read(&reused).unwrap(), fs::read(&fresh).unwrap());
        assert_eq!(dep_edges(&reused_edges), dep_edges(&fresh_edges));
        let full_distances = distances(&out.path().join("base"), &full, &edges);
        assert_eq!(full_distances, distances(&base, &reused, &reused_edges));
        actual.push(full_distances);
    }
    // Columns are holder, typed reader, registration, reader with an explicit
    // registration input, and the unconstrained reader using the default tool.
    let expected = if typed {
        [
            [None, Some(1), Some(1), Some(1), Some(1)],
            [Some(1), Some(1), Some(0), Some(1), Some(1)],
            [Some(3), None, None, None, None],
            [Some(3), Some(1), Some(1), Some(1), Some(1)],
        ]
    } else {
        // In legacy mode #619 reports the registration when its implementation
        // changes. Its ordinary reference is also the explicit reader's only path.
        [
            [Some(2), None, Some(1), Some(2), None],
            [Some(1), None, Some(0), Some(1), None],
            [Some(3), None, None, None, None],
            [Some(2), None, Some(1), Some(2), None],
        ]
    };
    assert_eq!(actual, expected);
}

#[test]
fn toolchain_declarations_follow_their_implementations() {
    let workspace = copy_workspace("extension_toolchain_through_owner");
    let root = workspace.path();
    edit(&root.join("MODULE.bazel"), |module| {
        format!("{module}\nregister_toolchains(\"//declaration:registration\")\n")
    });
    let out = tempfile::tempdir().unwrap();
    let before = out.path().join("before.json");
    let after = out.path().join("after.json");
    let edges = out.path().join("edges.json");
    let result = out.path().join("impacted.json");
    let args = [
        "--bazelCommandOptions=--noproto:flatten_selects",
        "--includeTargetType",
        "-d",
        edges.to_str().unwrap(),
    ];
    for (hashes, value) in [(&before, "before"), (&after, "after")] {
        if value == "after" {
            edit(&root.join("declaration/BUILD.bazel"), |text| {
                text.replace("\"before\"", "\"after\"")
            });
        }
        assert_product(
            root,
            "//declaration:consumer",
            "declaration/consumer.txt",
            value,
        );
        assert!(generate(root, hashes, &args).status.success());
    }
    assert!(impacted(
        root,
        &before,
        &after,
        &result,
        &["-d", edges.to_str().unwrap()]
    )
    .status
    .success());
    let changes: Vec<serde_json::Value> =
        serde_json::from_slice(&fs::read(result).unwrap()).unwrap();
    let distance = |name: &str| {
        changes
            .iter()
            .find(|row| row["label"] == name)
            .and_then(|row| row["targetDistance"].as_u64())
    };
    assert_eq!(distance("//declaration:primary"), Some(0));
    assert_eq!(distance("//declaration:registration"), Some(1));
    assert_eq!(distance("//declaration:choice"), Some(1));
    assert_eq!(distance("//declaration:other"), None);
    assert!(dep_edges(&edges)["//declaration:choice"].contains("//declaration:other"));
}

fn supports_static_toolchain_metadata(root: &std::path::Path) -> bool {
    let mod_help = std::process::Command::new(bazel())
        .current_dir(root)
        .args(["help", "mod"])
        .output()
        .unwrap();
    assert!(mod_help.status.success());
    if !String::from_utf8_lossy(&mod_help.stdout).contains("include_toolchain_registrations") {
        return false;
    }
    let types = std::process::Command::new(bazel())
        .current_dir(root)
        .args(["query", "set()", "--proto:possible_toolchain_types"])
        .output()
        .unwrap();
    if !types.status.success()
        && String::from_utf8_lossy(&types.stderr).contains("Unrecognized option")
    {
        return false;
    }
    assert!(
        types.status.success(),
        "{}",
        String::from_utf8_lossy(&types.stderr)
    );
    true
}

#[test]
fn provider_enrichment_does_not_fetch_an_unselected_alias_branch() {
    if !supports_mod_show_repo() {
        return;
    }
    let workspace = copy_workspace("cross_extension_toolchain");
    let root = workspace.path();
    let bazel_query = |args: &[&str]| {
        std::process::Command::new(bazel())
            .current_dir(root)
            .arg("query")
            .args(args)
            .output()
            .unwrap()
    };
    // The companion cross-extension case tests that a real registered
    // supplier still propagates its ordinary file input.
    if !supports_static_toolchain_metadata(root) {
        return;
    }
    edit(&root.join("assets/MODULE.bazel"), |s| {
        s.replace(
            "\"neighbor\", \"payload\"",
            "\"neighbor\", \"payload\", \"unavailable\"",
        )
    });
    edit(&root.join("assets/values.bzl"), |s| {
        s.replace(
            "def _values(ctx):",
            r#"def _unavailable(ctx):
    # Leave a durable signal even if generate-hashes recovers from a failed fetch.
    marker = ctx.workspace_root.get_child("provider-fetch-attempted")
    result = ctx.execute(["touch", str(marker)])
    if result.return_code:
        fail(result.stderr)
    fail("unselected_provider_repo_fetched")

_unavailable_repo = repository_rule(implementation = _unavailable)

def _values(ctx):
    _unavailable_repo(name = "unavailable")"#,
        )
    });
    edit(&root.join("assets/BUILD.bazel"), |s| {
        format!("config_setting(name = \"optional_sdk\", define_values = {{\"use_optional_sdk\": \"yes\"}})\n{}",
            s.replace("actual = \"@payload//:value.txt\"", r#"actual = select({":optional_sdk": "@unavailable//:missing", "//conditions:default": "@payload//:value.txt"})"#))
    });
    std::fs::write(
        root.join("assets/settings.bzl"),
        r#""""A flag for the registered tool's target settings."""

def _implementation(_ctx):
    return []

flag = rule(implementation = _implementation, build_setting = config.bool())
"#,
    )
    .unwrap();
    edit(&root.join("assets/BUILD.bazel"), |s| {
        format!(
            r#"load(":settings.bzl", "flag")
{s}
flag(name = "enabled_flag", build_setting_default = True)
alias(
    name = "sdk_flag",
    actual = select({{
        ":optional_sdk": "@unavailable//:missing",
        "//conditions:default": ":enabled_flag",
    }}),
)
config_setting(
    name = "supported",
    flag_values = {{":sdk_flag": "true"}},
    visibility = ["//visibility:public"],
)
"#
        )
    });
    edit(&root.join("sdk/tools.bzl"), |s| {
        s.replace(
            r#"toolchain(name = "registered","#,
            r#"toolchain(name = "registered", target_settings = ["@assets//:supported"],"#,
        )
    });
    assert_product(root, "//:products", "products.txt", "1A");
    let results = tempfile::tempdir().unwrap();
    let edge_file = results.path().join("edges");
    let output = generate(
        root,
        &results.path().join("hashes"),
        &["--depEdgesFile", edge_file.to_str().unwrap()],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let edges = dep_edges(&edge_file);
    let registration = "@@sdk++tools+sdk_registration//:registered";
    assert!(edges["//:consumer"].contains(registration));
    assert!(edges[registration].contains("@@sdk++tools+sdk_registration//:impl"));
    let projected = bazel_query(&[
        registration,
        "--output=streamed_jsonproto",
        "--consistent_labels",
        "--proto:output_rule_attrs=target_settings",
    ]);
    assert!(
        projected.status.success(),
        "{}",
        String::from_utf8_lossy(&projected.stderr)
    );
    let row: serde_json::Value = serde_json::from_slice(&projected.stdout).unwrap();
    let settings = row["rule"]["attribute"]
        .as_array()
        .unwrap()
        .iter()
        .find(|attr| attr["name"] == "target_settings")
        .unwrap();
    assert_eq!(
        settings["stringListValue"],
        serde_json::json!(["@@assets+//:supported"])
    );
    let setting_spellings = ["@assets//:supported", "@@assets+//:supported"];
    let flag_spellings = ["@assets//:sdk_flag", "@@assets+//:sdk_flag"];
    let owner = if settings["nodep"] == true {
        assert!(setting_spellings
            .iter()
            .all(|label| !edges[registration].contains(*label)));
        "//:consumer"
    } else {
        registration
    };
    let setting = edges[owner]
        .iter()
        .find(|label| setting_spellings.contains(&label.as_str()))
        .unwrap_or_else(|| panic!("{owner}: {:?}", edges[owner]));
    assert!(edges.contains_key(setting), "missing matcher row {setting}");
    let flag = edges[setting]
        .iter()
        .find(|label| flag_spellings.contains(&label.as_str()))
        .unwrap_or_else(|| panic!("{setting}: {:?}", edges[setting]));
    assert!(edges.contains_key(flag), "missing flag row {flag}");
    let marker = root.join("provider-fetch-attempted");
    assert!(
        !marker.exists(),
        "the inactive supplier repository was fetched"
    );
    let direct = bazel_query(&["@@assets++values+unavailable//:missing"]);
    assert!(!direct.status.success());
    assert!(String::from_utf8_lossy(&direct.stderr).contains("unselected_provider_repo_fetched"));
    assert!(
        marker.is_file(),
        "the direct control must exercise the fetch marker"
    );
}

#[test]
fn selected_tool_consumes_a_file_from_another_extension() {
    if !supports_mod_show_repo() {
        return;
    }
    let workspace = copy_workspace("cross_extension_toolchain");
    let profiles: [(&str, &[&str]); 2] = [
        ("default", &[]),
        (
            "projected",
            &[
                "--excludeExternalTargets",
                "--bazelCommandOptions=--curses=no --nokeep_going --proto:output_rule_attrs=tags --proto:include_synthetic_attribute_hash --noproto:locations",
            ],
        ),
    ];
    assert_cross_extension_impacts(workspace.path(), &profiles);
}

#[test]
fn stock_query_recovers_a_toolchain_reference_masked_by_an_ordinary_attribute() {
    let workspace = copy_workspace("cross_extension_toolchain");
    let root = workspace.path();
    if !supports_mod_show_repo() || supports_static_toolchain_metadata(root) {
        return;
    }
    // A label_flag can forward the type provider without being a native alias or toolchain_type.
    edit(&root.join("sdk/BUILD.bazel"), |build| {
        format!("{build}\nlabel_flag(name = \"type_flag\", build_setting_default = \":type\", visibility = [\"//visibility:public\"])\n")
    });
    edit(&root.join("sdk/defs.bzl"), |defs| {
        defs.replace("@sdk//:type", "@sdk//:type_flag").replace(
            "consumer = rule(implementation = _consumer,",
            "consumer = rule(implementation = _consumer, attrs = {\"type_ref\": attr.label()},",
        ) + r#"
def _ordinary(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.write(out, "plain")
    return [DefaultInfo(files = depset([out]))]

ordinary = rule(implementation = _ordinary, attrs = {"type_ref": attr.label()})
"#
    });
    fs::write(
        root.join("BUILD.bazel"),
        r#"load("@sdk//:defs.bzl", "consumer", "ordinary")
package(default_visibility = ["//:visible"])
package_group(name = "visible", packages = ["//..."])
consumer(name = "a_explicit", type_ref = "@sdk//:type_flag")
consumer(name = "b_implicit")
ordinary(name = "c_manual", type_ref = "@sdk//:type_flag")
ordinary(name = "d_plain")
filegroup(name = "neighbor", srcs = ["@assets//:neighbor"])
"#,
    )
    .unwrap();

    let out = tempfile::tempdir().unwrap();
    let labels = [
        "//:a_explicit",
        "//:b_implicit",
        "//:c_manual",
        "//:d_plain",
    ];
    let paths = ["1", "2"].map(|payload| {
        fs::write(
            root.join("versions.json"),
            format!(r#"{{"payload":"{payload}","neighbor":"A"}}"#),
        )
        .unwrap();
        let build = std::process::Command::new(bazel())
            .current_dir(root)
            .arg("build")
            .args(labels)
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        for (label, expected) in labels.iter().zip([payload, payload, "plain", "plain"]) {
            let name = label.strip_prefix("//:").unwrap();
            assert_eq!(
                fs::read_to_string(root.join(format!("bazel-bin/{name}.txt"))).unwrap(),
                expected,
                "{label}"
            );
        }
        let path = out.path().join(payload);
        let result = generate(root, &path, &[]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        path
    });
    let [base, head] = paths.each_ref().map(|path| hashes(path));
    for label in labels {
        assert_eq!(
            base[label].rsplit_once('~').unwrap().1,
            head[label].rsplit_once('~').unwrap().1,
            "unchanged rule definition for {label}"
        );
    }
    let changed = out.path().join("impacted");
    let result = impacted(root, &paths[0], &paths[1], &changed, &[]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let affected = read_lines(&changed);
    let has = |label: &str| {
        affected
            .iter()
            .any(|item| item.trim_start_matches('@') == label)
    };
    assert!(has(labels[0]) && has(labels[1]), "{affected:?}");
    // The explicit ordinary referrer may retain a conservative repository dependency.
    assert!(!has(labels[3]), "{affected:?}");
}

#[test]
fn unavailable_toolchain_body_changes_the_reader_and_spares_the_holder() {
    let workspace = copy_workspace("cross_extension_toolchain");
    let root = workspace.path();
    if !supports_mod_show_repo() || !supports_static_toolchain_metadata(root) {
        return;
    }
    fs::write(root.join("sdk/tools.bzl"), r#""""Declare the registered provider in a separate generated repository."""

def _body(ctx):
    ctx.file("BUILD.bazel", """load("@sdk//:defs.bzl", "sdk_tool")
sdk_tool(name = "impl", payload = "@assets//:payload", visibility = ["//visibility:public"])
""")

_body_repo = repository_rule(implementation = _body)

def _registration(ctx):
    ctx.file("BUILD.bazel", """toolchain(name = "registered", toolchain = "@hidden_body//:impl", toolchain_type = "@sdk//:type", visibility = ["//visibility:public"])
""")

_registration_repo = repository_rule(implementation = _registration)

def _tools(_ctx):
    _body_repo(name = "hidden_body")
    _registration_repo(name = "sdk_registration")

tools = module_extension(implementation = _tools)
"#).unwrap();
    fs::write(
        root.join("holder.bzl"),
        r#""""Expose the declared registration label without using a toolchain."""

def _holder(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.write(out, ctx.attr.registration.label.name)
    return [DefaultInfo(files = depset([out]))]

holder = rule(
    implementation = _holder,
    attrs = {"registration": attr.label(mandatory = True)},
)
"#,
    )
    .unwrap();
    edit(&root.join("BUILD.bazel"), |build| {
        format!(
            r#"load(":holder.bzl", "holder")
{build}
holder(name = "holder", registration = "@@sdk++tools+sdk_registration//:registered")
"#
        )
    });

    let output = tempfile::tempdir().unwrap();
    let before = output.path().join("before");
    let after = output.path().join("after");
    for (path, payload) in [(&before, "1"), (&after, "2")] {
        fs::write(
            root.join("versions.json"),
            format!(r#"{{"payload":"{payload}","neighbor":"A"}}"#),
        )
        .unwrap();
        assert_product(root, "//:products", "products.txt", &format!("{payload}A"));
        assert_product(root, "//:holder", "holder.txt", "registered");
        let result = generate(root, path, &[]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    let declared = "@@sdk++tools+sdk_registration//:registered";
    let implementation = "@@sdk++tools+hidden_body//:impl";
    let repository = "//external:sdk++tools+hidden_body";
    let base = hashes(&before);
    let head = hashes(&after);
    assert!(!base.contains_key(implementation) && !head.contains_key(implementation));
    assert_eq!(base[repository], head[repository]);
    assert_eq!(base[declared], head[declared]);

    let selected = output.path().join("impacted");
    assert!(impacted(root, &before, &after, &selected, &[])
        .status
        .success());
    let labels = read_lines(&selected);
    let has = |name| {
        labels
            .iter()
            .any(|label| label.trim_start_matches('@') == name)
    };
    assert!(has("//:consumer") && has("//:products"), "{labels:?}");
    assert!(!has("//:holder") && !has("//:neighbor"), "{labels:?}");
}

#[test]
fn registered_implementations_can_live_in_other_reached_packages() {
    if !supports_mod_show_repo() {
        return;
    }
    // The generated declaration's own repository, then a different module whose
    // neighbor is already referenced by the main workspace.
    for implementation in ["//body:impl", "@assets//body:impl"] {
        let workspace = copy_workspace("cross_extension_toolchain");
        let root = workspace.path();
        if !supports_static_toolchain_metadata(root) {
            return;
        }
        let body = r#"load("@@sdk+//:defs.bzl", "sdk_tool")
sdk_tool(name = "impl", payload = "@assets//:payload", visibility = ["//visibility:public"])
"#;
        let foreign_package = root.join("assets/body");
        fs::create_dir(&foreign_package).unwrap();
        fs::write(foreign_package.join("BUILD.bazel"), body).unwrap();
        edit(&root.join("sdk/tools.bzl"), |source| {
            let (_, extension) = source.split_once("_registration_repo = ").unwrap();
            format!(
                r#"def _registration(ctx):
    ctx.file("body/BUILD.bazel", """{body}""")
    ctx.file("BUILD.bazel", """toolchain(name = "registered", toolchain = "{implementation}", toolchain_type = "@sdk//:type")
""")

_registration_repo = {extension}"#
            )
        });
        let results = tempfile::tempdir().unwrap();
        let edges = results.path().join("edges");
        let options = ["--depEdgesFile", edges.to_str().unwrap()];
        assert_cross_extension_impacts(root, &[("default", &options)]);
        let graph = dep_edges(&edges);
        let registration = "@@sdk++tools+sdk_registration//:registered";
        let reader = &graph["//:consumer"];
        assert!(reader.contains(registration));
        let body = reader
            .iter()
            .find(|input| input.ends_with("//body:impl"))
            .expect("the typed reader must keep its observed implementation edge");
        assert!(graph.contains_key(body));
        assert!(graph[registration].contains(body));
    }
}

#[test]
fn same_type_registrations_preserve_the_selected_foreign_payload() {
    if !supports_mod_show_repo() {
        return;
    }
    let workspace = copy_workspace("cross_extension_toolchain");
    let root = workspace.path();
    if !supports_static_toolchain_metadata(root) {
        return;
    }
    // The alternate also requires a platform value from the module that generates
    // payload and neighbor. Only a change to the value should affect its eligibility.
    let constraints = root.join("assets/constraints");
    fs::create_dir(&constraints).unwrap();
    let definition = constraints.join("BUILD.bazel");
    fs::write(
        &definition,
        r#"package(default_visibility = ["//visibility:public"])

constraint_setting(name = "abi", default_constraint_value = ":generic")
constraint_value(name = "generic", constraint_setting = ":abi")
constraint_value(name = "special", constraint_setting = ":abi")
"#,
    )
    .unwrap();
    edit(&root.join("sdk/MODULE.bazel"), |module| {
        module.replace(
            "register_toolchains(",
            "register_toolchains(\"//:alternate_registration\", ",
        )
    });
    edit(&root.join("sdk/BUILD.bazel"), |build| {
        format!(
            r#"load(":defs.bzl", "sdk_tool")
{build}
config_setting(name = "alternate", define_values = {{"use_alternate_sdk": "yes"}})
sdk_tool(name = "alternate_impl", payload = "alternate.txt")
toolchain(
    name = "alternate_registration",
    target_settings = [":alternate"],
    exec_compatible_with = ["@assets//constraints:generic"],
    toolchain = ":alternate_impl",
    toolchain_type = ":type",
)
"#
        )
    });
    fs::write(root.join("sdk/alternate.txt"), "alternate").unwrap();
    // Put the alternate first and prove it can win. The ordinary products below
    // then use the foreign payload because this target setting does not match.
    let assert_configured_consumer = |expected: &str| {
        let selected = std::process::Command::new(bazel())
            .current_dir(root)
            .args(["build", "--define=use_alternate_sdk=yes", "//:consumer"])
            .output()
            .unwrap();
        assert!(
            selected.status.success(),
            "{}",
            String::from_utf8_lossy(&selected.stderr)
        );
        assert_eq!(
            fs::read_to_string(root.join("bazel-bin/consumer.txt")).unwrap(),
            expected
        );
    };
    assert_configured_consumer("alternate");
    assert_cross_extension_impacts(root, &[("default", &[])]);
    let output = tempfile::tempdir().unwrap();
    let before = output.path().join("before");
    let after = output.path().join("after");
    let edges = output.path().join("edges");
    assert!(
        generate(root, &before, &["--depEdgesFile", edges.to_str().unwrap()])
            .status
            .success()
    );
    let graph = dep_edges(&edges);
    let (_, inputs) = graph
        .iter()
        .find(|(label, _)| label.ends_with("//:alternate_registration"))
        .unwrap();
    let condition = inputs
        .iter()
        .find(|label| label.ends_with("//constraints:generic"))
        .unwrap();
    let setting = graph[condition]
        .iter()
        .find(|label| label.ends_with("//constraints:abi"))
        .unwrap();

    edit(&definition, |build| {
        build.replace(
            "default_constraint_value = \":generic\"",
            "default_constraint_value = \":special\"",
        )
    });
    assert_configured_consumer("1");
    assert!(generate(root, &after, &[]).status.success());
    let before_hashes = hashes(&before);
    let after_hashes = hashes(&after);
    assert_ne!(
        before_hashes[setting].rsplit_once('~').unwrap().1,
        after_hashes[setting].rsplit_once('~').unwrap().1
    );
    assert_ne!(before_hashes[condition], after_hashes[condition]);
    let result = output.path().join("impacted");
    assert!(impacted(root, &before, &after, &result, &[])
        .status
        .success());
    assert!(read_lines(&result)
        .iter()
        .any(|label| label.trim_start_matches('@') == "//:consumer"));
}

fn assert_cross_extension_impacts(root: &std::path::Path, profiles: &[(&str, &[&str])]) {
    let out = tempfile::tempdir().unwrap();
    for (arm, payload, neighbor) in [
        ("base", "1", "A"),
        ("payload", "2", "A"),
        ("neighbor", "1", "B"),
    ] {
        fs::write(
            root.join("versions.json"),
            format!(r#"{{"payload":"{payload}","neighbor":"{neighbor}"}}"#),
        )
        .unwrap();
        assert_product(
            root,
            "//:products",
            "products.txt",
            &format!("{payload}{neighbor}"),
        );
        for &(profile, options) in profiles {
            let generated = generate(root, &out.path().join(format!("{profile}-{arm}")), options);
            assert!(
                generated.status.success(),
                "profile={profile}, arm={arm}: {}",
                String::from_utf8_lossy(&generated.stderr)
            );
        }
    }
    let typed = supports_static_toolchain_metadata(root);
    for &(profile, _) in profiles {
        for arm in ["payload", "neighbor"] {
            let affected = out.path().join(format!("{profile}-impact"));
            let result = impacted(
                root,
                &out.path().join(format!("{profile}-base")),
                &out.path().join(format!("{profile}-{arm}")),
                &affected,
                &[],
            );
            assert!(
                result.status.success(),
                "profile={profile}, arm={arm}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let labels = read_lines(&affected);
            let has = |target| {
                labels
                    .iter()
                    .any(|name| name.trim_start_matches('@') == target)
            };
            assert_eq!(
                has("//:neighbor"),
                arm == "neighbor",
                "{profile} {arm}: {labels:?}"
            );
            assert!(has("//:products"), "{profile} {arm}: {labels:?}");
            if arm == "payload" {
                assert!(has("//:consumer"), "{profile} {arm}: {labels:?}");
            } else if typed {
                assert!(!has("//:consumer"), "{profile} {arm}: {labels:?}");
            }
        }
    }
}

#[test]
fn unresolved_import_keeps_a_hidden_tool_without_an_ordinary_owner_input() {
    if !supports_mod_show_repo() {
        return;
    }
    let workspace = copy_workspace("extension_toolchain_through_owner");
    let root = workspace.path();
    let defs = fs::read_to_string(root.join("ext/defs.bzl")).unwrap();
    fs::write(
        root.join("owner_free.bzl"),
        defs.replace("@ext//:toolchain_type", "@@//:hidden_type")
            .replace("    attrs = {\"_wrapper\": attr.label(default = \"@ext//:wrapper.sh\", allow_single_file = True)},\n", ""),
    )
    .unwrap();
    edit(&root.join("ext/tools.bzl"), |source| {
        source
            .replace(
                "def _app_impl(rctx):",
                "def _app_impl(rctx):\n    rctx.file(\"template.txt\", \"VERSION\")",
            )
            .replace(
                "app_lib(name = ",
                "exports_files([\"template.txt\"])\napp_lib(name = ",
            )
            .replace(
                r#"app_lib(name = "lib", visibility = ["//visibility:public"])"#,
                r#"app_lib(name = "lib", visibility = ["//visibility:public"])
alias(name = "forward_alias", actual = ":lib")
filegroup(name = "forward", srcs = [":forward_alias"], visibility = ["//visibility:public"])
filegroup(name = "cycle_a", srcs = [":cycle_b"], visibility = ["//visibility:public"])
filegroup(name = "cycle_b", srcs = [":cycle_a"])
config_setting(name = "optional", define_values = {"use_unselected_app": "yes"})
alias(
    name = "conditional",
    actual = select({":optional": "@unselected_app//:lib", "//conditions:default": ":lib"}),
    visibility = ["//visibility:public"],
)"#,
            )
            .replace("@ext//:defs.bzl", "@@//:owner_free.bzl")
            .replace("@ext//:toolchain_type", "@@//:hidden_type")
            .replace(
                "def _tools_impl(mctx):",
                r#"def _unavailable_impl(rctx):
    marker = rctx.workspace_root.get_child("hidden-reader-fetch-attempted")
    result = rctx.execute(["touch", str(marker)])
    if result.return_code:
        fail(result.stderr)
    fail("unselected_filegroup_repo_fetched")

unavailable = repository_rule(implementation = _unavailable_impl)

def _tools_impl(mctx):"#,
            )
            .replace(
                "    app(name = \"app\")",
                "    app(name = \"app\")\n    app(name = \"nested_app\")\n    unavailable(name = \"unselected_app\")",
            )
            .replace(
                r#"tc(name = "tc", version = versions["toolchain"])"#,
                r#"tc(name = "tc", version = "stable")"#,
            )
    });
    fs::write(
        root.join("ext/MODULE.bazel"),
        "module(name = \"ext\")\nregister_toolchains(\"@@ext++tools+tc_alias//:tc\")\n",
    )
    .unwrap();
    edit(&root.join("BUILD.bazel"), |build| {
        format!(
            r#"{build}
toolchain_type(name = "hidden_type", visibility = ["//visibility:public"])
filegroup(name = "only_template", srcs = ["@app//:template.txt"])
# One stable imported file alongside a tool-using library in an unimported repository.
filegroup(name = "nested", srcs = [":only_template", "@@ext++tools+nested_app//:forward"])
genrule(
    name = "product", srcs = [":nested"], outs = ["product.txt"],
    cmd = 'for f in $(locations :nested); do case "$$f" in */lib.txt) cat "$$f";; esac; done > "$@"',
)
filegroup(name = "cycle", srcs = ["@@ext++tools+nested_app//:cycle_a"])
filegroup(name = "conditional", srcs = ["@@ext++tools+nested_app//:conditional"])
genrule(name = "conditional_product", srcs = [":conditional"], outs = ["conditional.txt"], cmd = "cat $< > $@")
"#
        )
    });
    let output = tempfile::tempdir().unwrap();
    let typed_metadata = supports_static_toolchain_metadata(root);
    let profiles = [("default", false), ("fine", true)];
    for value in ["A", "B"] {
        fs::write(
            root.join("versions.json"),
            format!(r#"{{"toolchain":"{value}"}}"#),
        )
        .unwrap();
        assert_product(root, "//:product", "product.txt", value);
        assert_product(root, "//:conditional_product", "conditional.txt", value);
        for (profile, fine) in profiles {
            let name = format!("{profile}-{value}");
            let edges = output.path().join(format!("{name}-edges"));
            let mut flags = vec!["--depEdgesFile", edges.to_str().unwrap()];
            if fine {
                flags.extend(["--fineGrainedHashExternalRepos", "@app"]);
            }
            let result = generate(root, &output.path().join(name), &flags);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(
                !root.join("hidden-reader-fetch-attempted").exists(),
                "literal reader lookup fetched an unselected filegroup branch"
            );
        }
    }
    for (profile, _) in profiles {
        let base_path = output.path().join(format!("{profile}-A"));
        let head_path = output.path().join(format!("{profile}-B"));
        let base = hashes(&base_path);
        let head = hashes(&head_path);
        let hidden = "//external:ext++tools+nested_app";
        assert_eq!(
            base.get(hidden).expect("hidden app repository"),
            head.get(hidden).expect("hidden app repository")
        );
        let sdk = "//external:ext++tools+tc_impl";
        fn direct(value: &str) -> &str {
            value.rsplit_once('~').map_or(value, |(_, direct)| direct)
        }
        assert_ne!(
            direct(base.get(sdk).expect("hidden SDK repository")),
            direct(head.get(sdk).expect("hidden SDK repository"))
        );
        let affected = output.path().join(format!("{profile}-impact"));
        let result = impacted(root, &base_path, &head_path, &affected, &[]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let labels = read_lines(&affected);
        let graph = dep_edges(&output.path().join(format!("{profile}-B-edges")));
        for required in [
            "//:uses_app",
            "//:nested",
            "//:product",
            "//:conditional",
            "//:conditional_product",
        ] {
            assert!(
                labels
                    .iter()
                    .any(|label| label.trim_start_matches('@') == required),
                "{profile}: missing {required}: {labels:?}"
            );
        }
        if typed_metadata {
            let chain = [
                "//:nested",
                "@@ext++tools+nested_app//:forward",
                "@@ext++tools+nested_app//:forward_alias",
                "@@ext++tools+nested_app//:lib",
                "@@ext++tools+tc_alias//:tc",
            ];
            for edge in chain.windows(2) {
                assert!(
                    graph
                        .get(edge[0])
                        .is_some_and(|inputs| inputs.contains(edge[1])),
                    "missing {} -> {}",
                    edge[0],
                    edge[1]
                );
            }
            assert!(graph["//:uses_app"].contains("@app//:lib"));
        }
        assert!(
            !labels
                .iter()
                .any(|label| label.trim_start_matches('@') == "//:only_template"),
            "{profile}: unchanged forwarding target selected: {labels:?}; template={:?}; repository={:?}",
            graph.get("//:only_template"),
            graph.get("//external:app")
        );
    }
    let unavailable = std::process::Command::new(bazel())
        .current_dir(root)
        .args(["query", "@@ext++tools+unselected_app//:lib"])
        .output()
        .unwrap();
    assert!(!unavailable.status.success());
    assert!(
        String::from_utf8_lossy(&unavailable.stderr).contains("unselected_filegroup_repo_fetched")
    );
    assert!(root.join("hidden-reader-fetch-attempted").exists());
}

// Module `ext` registers a toolchain for the app its extension generates. The app must
// see the active SDK change under each spelling of that registration. Opting in
// to a different, root-isolated usage must preserve this dependency.
#[test]
fn fine_grained_extension_target_sees_a_toolchain_from_its_extension() {
    if !supports_mod_show_repo() {
        return;
    }
    for registration in [
        "use_repo(tools, \"tc\")\nregister_toolchains(\"@tc//:all\")",
        "use_repo(tools, \"tc_alias\")\nregister_toolchains(\"@tc_alias//:tc\")",
        "register_toolchains(\"@@ext++tools+tc//:tc\")",
    ] {
        let first = copy_workspace("extension_toolchain_through_owner");
        let bumped = copy_workspace("extension_toolchain_through_owner");
        let isolated_peer = registration.starts_with("register_toolchains");
        for workspace in [&first, &bumped] {
            fs::write(
                workspace.path().join("ext/MODULE.bazel"),
                format!(
                    "module(name = \"ext\")\n\ntools = use_extension(\"//:tools.bzl\", \"tools\")\n{registration}\n"
                ),
            )
            .unwrap();
            if isolated_peer {
                edit(&workspace.path().join("MODULE.bazel"), |module| {
                    format!(
                        "{module}\npeer = use_extension(\"@ext//:tools.bzl\", \"tools\", isolate = True)\npeer.lock(file = \"//:peer_versions.json\")\nuse_repo(peer, peer_tc = \"tc\")\n"
                    )
                });
                fs::write(
                    workspace.path().join(".bazelrc"),
                    "common --experimental_isolated_extension_usages\n",
                )
                .unwrap();
                fs::write(
                    workspace.path().join("peer_versions.json"),
                    r#"{"toolchain":"1.0"}"#,
                )
                .unwrap();
                edit(&workspace.path().join("BUILD.bazel"), |build| {
                    format!("{build}\ngenrule(name = \"product\", srcs = [\":uses_app\"], outs = [\"version.txt\"], cmd = \"cat $< > $@\")\n")
                });
            }
        }
        edit(&bumped.path().join("versions.json"), |text| {
            text.replace("1.0", "2.0")
        });
        let ordinary = diff_local(
            first.path(),
            bumped.path(),
            &["--fineGrainedHashExternalRepos", "@app"],
        );
        assert!(
            ordinary
                .iter()
                .any(|label| label == "//:uses_app" || label == "@@//:uses_app"),
            "{registration}: {ordinary:?}"
        );
        if isolated_peer {
            let options = [
                "--fineGrainedHashExternalRepos",
                "@app",
                "--isolatedDependencyRoot",
                "@peer_tc",
            ];
            let has = |labels: &BTreeSet<String>, label: &str| {
                labels
                    .iter()
                    .any(|selected| selected.trim_start_matches('@') == label)
            };
            assert_product(first.path(), "//:product", "version.txt", "1.0");
            assert_product(bumped.path(), "//:product", "version.txt", "2.0");
            let out = tempfile::tempdir().unwrap();
            let from = out.path().join("base");
            let checked = |result: std::process::Output| {
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
            };
            checked(generate(first.path(), &from, &options));
            let changes = |arm: &str| {
                let to = out.path().join(arm);
                let affected = out.path().join(format!("{arm}-impact"));
                checked(generate(bumped.path(), &to, &options));
                checked(impacted(bumped.path(), &from, &to, &affected, &[]));
                read_lines(&affected)
            };
            let active = changes("active");
            assert!(has(&active, "//:uses_app"), "{active:?}");
            assert!(!has(&active, "peer_tc//:impl"), "{active:?}");

            // The isolated usage changes independently of the registered SDK.
            edit(&bumped.path().join("versions.json"), |text| {
                text.replace("2.0", "1.0")
            });
            edit(&bumped.path().join("peer_versions.json"), |text| {
                text.replace("1.0", "2.0")
            });
            assert_product(bumped.path(), "//:product", "version.txt", "1.0");
            let peer = changes("peer");
            assert!(has(&peer, "peer_tc//:impl"), "{peer:?}");
            assert!(!has(&peer, "//:uses_app"), "{peer:?}");
        }
    }
}

fn diff_local(
    first: &std::path::Path,
    second: &std::path::Path,
    args: &[&str],
) -> BTreeSet<String> {
    let output = tempfile::tempdir().unwrap();
    let from = output.path().join("from.json");
    let to = output.path().join("to.json");
    let result = output.path().join("impacted.txt");
    assert!(generate(first, &from, args).status.success());
    assert!(generate(second, &to, args).status.success());
    assert!(impacted(second, &from, &to, &result, &[]).status.success());
    read_lines(&result)
}

#[test]
fn external_macro_stack_uses_returned_source() {
    if !supports_mod_show_repo() {
        return;
    }
    let base = copy_workspace("external_macro_stack");
    let changed = copy_workspace("external_macro_stack");
    edit(&changed.path().join("defs.bzl"), |text| {
        text.replace(
            "right, \"//conditions:default\": left",
            "left, \"//conditions:default\": right",
        )
    });
    assert_product(base.path(), "//:product", "product.txt", "left");
    assert_product(changed.path(), "//:product", "product.txt", "right");
    let impacted = diff_local(
        base.path(),
        changed.path(),
        &[
            "--fineGrainedHashExternalRepos=@bridge,@macros",
            "--bazelStartupOptions=--ignore_all_rc_files",
        ],
    );
    let contains = |name| {
        impacted
            .iter()
            .any(|label| label.trim_start_matches('@') == name)
    };
    assert!(contains("//:uses_bridge"), "{impacted:?}");
    assert!(!contains("//:unrelated"), "{impacted:?}");
}

#[test]
fn returned_external_source_reaches_consumer() {
    let workspace = copy_workspace("returned_external_source");
    let output = tempfile::tempdir().unwrap();
    let before = output.path().join("before.json");
    let after = output.path().join("after.json");
    let result = output.path().join("impacted.txt");
    let args = [
        "--useCquery",
        "--cqueryExpression",
        "deps(set(//:consumer //:unrelated))",
    ];
    for (contents, snapshot) in [("before\n", &before), ("after\n", &after)] {
        fs::write(workspace.path().join("value.txt"), contents).unwrap();
        assert!(generate(workspace.path(), snapshot, &args).status.success());
        assert!(std::process::Command::new(bazel())
            .current_dir(workspace.path())
            .args(["build", "//:consumer"])
            .status()
            .unwrap()
            .success());
        assert_eq!(
            fs::read_to_string(workspace.path().join("bazel-bin/copied.txt")).unwrap(),
            contents
        );
    }
    assert!(impacted(workspace.path(), &before, &after, &result, &[])
        .status
        .success());
    let targets = read_lines(&result);
    assert!(
        targets.iter().any(|t| t.ends_with("//:mirror.txt")),
        "{targets:?}"
    );
    assert!(
        targets.contains("@@//:consumer") || targets.contains("//:consumer"),
        "{targets:?}"
    );
    assert!(!targets.contains("@@//:unrelated") && !targets.contains("//:unrelated"));
}
