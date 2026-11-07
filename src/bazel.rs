use crate::cancel::{self, Cancellation};
use crate::proto::analysis::{ConfiguredTarget, CqueryResult};
use crate::proto::blaze_query::{
    target, Attribute, ConfiguredRuleInput, PackageGroup, Repository, Rule, Target,
};
use anyhow::{anyhow, bail, Context, Result};
use buffa::Message;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::time::Instant;
use tempfile::NamedTempFile;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct BazelVersion(u32, u32, u32);

enum QueryFormat {
    Ordinary { keep_class_keys: bool },
    Configured,
    Walked,
}

#[derive(Debug)]
struct QueryFailure {
    code: Option<i32>,
    stderr: String,
}
impl std::fmt::Display for QueryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Bazel query failed, exit code {}: {}",
            self.code.unwrap_or(-1),
            self.stderr
        )
    }
}
impl std::error::Error for QueryFailure {}

/// The flag that decides whether the `//external` package exists.
const WORKSPACE_FLAG: &str = "enable_workspace";

/// What one `bazel info release output_base starlark-semantics` reports. Generation asks for
/// these together before querying so that the same call replaces `bazel version`, the later
/// `bazel info output_base` of the hashing pass, and -- when WORKSPACE is known to be disabled --
/// the `//external:all-targets` query that would only fail and be retried without it.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ServerInfo {
    version: Option<BazelVersion>,
    pub(crate) output_base: Option<PathBuf>,
    /// Whether `//external` exists. `None` when it cannot be told from `bazel info` alone, which
    /// keeps the query probing for it.
    external_package: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct BazelOptions {
    pub workspace: PathBuf,
    pub bazel: PathBuf,
    pub startup_options: Vec<String>,
    pub command_options: Vec<String>,
    pub cquery_options: Vec<String>,
    pub use_cquery: bool,
    pub cquery_expression: Option<String>,
    pub keep_going: bool,
    pub fine_grained_external_repos: BTreeSet<String>,
    /// Module extensions, as `bazel mod show_extension` names them
    /// (`@rules_rs//rs:extensions.bzl%crate`), whose repositories use each other only through
    /// labels: no target resolves a toolchain from one of them. The module that owns such an
    /// extension then does not stand in for its repositories (see `lower_repositories`).
    pub label_only_module_extensions: BTreeSet<String>,
    /// A root-isolated extension import whose external consumers are discoverable through
    /// ordinary target inputs and BUILD loads.
    pub isolated_dependency_root: Option<String>,
    pub exclude_external_targets: bool,
    pub exclude_targets_query: Option<String>,
    pub no_bazelrc: bool,
    pub verbose: bool,
    /// Set by `bazel-diff serve` for the query being answered: every Bazel subprocess is run
    /// through it so an abandoned query can kill them. `None` for the CLI commands.
    pub cancellation: Option<Arc<Cancellation>>,
}

impl BazelOptions {
    fn command(&self) -> Command {
        let mut command = Command::new(&self.bazel);
        command.current_dir(&self.workspace);
        if self.no_bazelrc {
            command.arg(if cfg!(windows) {
                "--bazelrc=NUL"
            } else {
                "--bazelrc=/dev/null"
            });
        }
        command.args(&self.startup_options);
        command
    }

    fn run_capture(&self, args: &[&str]) -> Result<Output> {
        let mut command = self.command();
        command.args(args).stdin(Stdio::null());
        if self.verbose {
            eprintln!("[Info] Command: {command:?}");
        }
        self.run(&mut command)
            .with_context(|| format!("failed to execute {}", self.bazel.display()))
    }

    /// Runs a Bazel command like `Command::output`, through the request's cancellation token when
    /// there is one.
    fn run(&self, command: &mut Command) -> io::Result<Output> {
        cancel::output(self.cancellation.as_deref(), command)
    }

    /// [`run`](Self::run) for a command whose stdout is redirected to a file.
    fn run_configured(&self, command: &mut Command) -> io::Result<Output> {
        cancel::output_configured(self.cancellation.as_deref(), command)
    }

    /// Fails once the query these options belong to has been cancelled, so a phase without a
    /// subprocess to kill still stops promptly.
    pub fn check_cancelled(&self) -> Result<()> {
        if let Some(token) = &self.cancellation {
            token.check()?;
        }
        Ok(())
    }

    /// Whether the workspace resolves its dependencies through Bzlmod.
    ///
    /// Probed with `bazel mod dump_repo_mapping ""`, which needs module resolution only.
    /// `bazel mod graph` evaluates every module extension in the dependency graph first, so a
    /// broken extension no target uses -- one a lazy `bazel build //...` never touches -- made
    /// it exit 2 and read as "Bzlmod disabled", silently dropping every `//external:` node
    /// (#531). `mod graph` stays as the fallback for a Bazel without `dump_repo_mapping`,
    /// taking the partial answer it gives over such an extension.
    pub fn is_bzlmod_enabled(&self) -> bool {
        let (enabled, _root_mapping) = self.probe_bzlmod();
        enabled
    }

    fn probe_bzlmod(&self) -> (bool, Option<Vec<u8>>) {
        if let Ok(output) = self.run_capture(&["mod", "dump_repo_mapping", ""]) {
            if output.status.success() {
                return (true, Some(output.stdout));
            }
        }
        let enabled = self
            .run_capture(&["mod", "graph"])
            .map(|output| {
                output.status.success()
                    || extension_failure(&String::from_utf8_lossy(&output.stderr))
                        .is_some_and(|failure| failure.answered)
            })
            .unwrap_or(false);
        (enabled, None)
    }

    /// For a module workspace the hashing pass needs the graph and the root and module
    /// mappings. Ask Bazel for those mappings together when the graph's module names fit
    /// in one call. Only actual mapping answers are used; a rejected or incomplete batch
    /// falls back to the independent root probe, including for a broken unused extension.
    fn probe_query_repositories(
        &self,
        supported: bool,
        survey: &mut ModuleSurvey,
    ) -> Result<(bool, Option<Vec<u8>>)> {
        if supported && self.workspace.join("MODULE.bazel").is_file() {
            (survey.graph, survey.toolchain_registrations) = self.module_graph_output()?;
            if let Some(prefetched) = survey
                .graph
                .as_ref()
                .and_then(|graph| self.prefetch_module_mappings(graph))
            {
                let (root, mappings) = prefetched;
                survey.mappings = mappings;
                return Ok((true, Some(root)));
            }
        }
        Ok(self.probe_bzlmod())
    }

    fn prefetch_module_mappings(
        &self,
        graph: &Output,
    ) -> Option<(Vec<u8>, BTreeMap<String, RepoMapping>)> {
        let complete = |output: &Output| {
            output.status.success() && !String::from_utf8_lossy(&output.stderr).contains("ERROR:")
        };
        if !complete(graph) {
            return None;
        }
        let candidates =
            hidden_module_repo_names(&String::from_utf8_lossy(&graph.stdout), &BTreeMap::new())
                .into_values()
                .filter(|name| !is_extension_repo(name))
                .collect::<BTreeSet<_>>();
        let size = 1 + candidates.iter().map(|name| name.len() + 1).sum::<usize>();
        if candidates.is_empty() || size > mod_argument_byte_budget() {
            return None;
        }
        let mut args = vec!["mod", "dump_repo_mapping", ""];
        args.extend(candidates.iter().map(String::as_str));
        let output = self.run_capture(&args).ok()?;
        if !complete(&output) {
            return None;
        }
        // Bazel prints one JSON object per argument, in order. Keep the root's
        // original bytes for external hashing and reject partial or extra rows.
        let mut rows = output.stdout.split_inclusive(|&byte| byte == b'\n');
        let root = rows.next()?;
        serde_json::from_slice::<RepoMapping>(root).ok()?;
        let mut mappings = BTreeMap::new();
        for name in candidates {
            mappings.insert(name, serde_json::from_slice(rows.next()?).ok()?);
        }
        rows.next().is_none().then(|| (root.to_vec(), mappings))
    }

    /// The module graph for the hash file's metadata. A failed module extension is reported
    /// by the hashing pass, so this one takes the partial answer silently.
    pub fn module_graph_json(&self) -> Option<String> {
        let output = self.run_capture(&["mod", "graph", "--output=json"]).ok()?;
        Self::answered_module_graph(output)
    }

    fn answered_module_graph(output: Output) -> Option<String> {
        let answered = output.status.success()
            || extension_failure(&String::from_utf8_lossy(&output.stderr))
                .is_some_and(|failure| failure.answered);
        answered.then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn optional_toolchain_response(&self, args: &[&str]) -> Result<Option<Output>> {
        let output = match self.run_capture(args) {
            Ok(output) => output,
            Err(error) => {
                self.check_cancelled()?;
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::Interrupted)
                {
                    return Err(error);
                }
                if self.verbose {
                    eprintln!("[Warn] Optional toolchain input is unavailable: {error:#}");
                }
                return Ok(None);
            }
        };
        self.check_cancelled()?;
        // Bazel uses exit code 8 for interruption; a signal has no exit code.
        if matches!(output.status.code(), None | Some(8)) {
            bail!("Bazel toolchain input acquisition was interrupted");
        }
        Ok(Some(output))
    }

    fn optional_toolchain_output(&self, args: &[&str]) -> Result<Option<Output>> {
        Ok(self.optional_toolchain_response(args)?.filter(|output| {
            output.status.success() && !String::from_utf8_lossy(&output.stderr).contains("ERROR:")
        }))
    }

    /// Query-only repository or configuration overrides are not applied to the module survey.
    /// Static supplier evidence is available only when command options change serialization.
    pub(crate) fn static_toolchain_scope_matches(&self) -> bool {
        self.isolated_dependency_root.is_none()
            && self.command_options.iter().all(|option| {
                option.starts_with("--proto:")
                    || option.starts_with("--noproto:")
                    || option == "--consistent_labels"
                    || option.starts_with("--order_output=")
                    || option.starts_with("--curses=")
                    || option == "--nokeep_going"
            })
    }

    pub(crate) fn can_use_observed_inputs(&self) -> bool {
        if self.use_cquery
            || self.keep_going
            || !self.static_toolchain_scope_matches()
            || self
                .exclude_targets_query
                .as_deref()
                .is_some_and(|exclude| !exclude.trim().is_empty())
        {
            return false;
        }
        // Bazel applies the last Boolean option. Suppressed ordinary inputs cannot
        // establish the named boundaries used by supplier subscriptions.
        let ordinary_inputs =
            self.command_options
                .iter()
                .rev()
                .find_map(|option| match option.as_str() {
                    "--noproto:rule_inputs_and_outputs" => Some(false),
                    "--proto:rule_inputs_and_outputs" => Some(true),
                    other => other
                        .strip_prefix("--proto:rule_inputs_and_outputs=")
                        .map(|value| {
                            ["true", "1", "yes", "t", "y"]
                                .iter()
                                .any(|enabled| value.eq_ignore_ascii_case(enabled))
                        }),
                });
        ordinary_inputs != Some(false)
    }

    /// A successful enhanced response contains the ordinary graph plus one registration field.
    /// Reuse any answered ordinary graph for parsed consumers, while registration evidence
    /// requires a complete response. Otherwise use the ordinary command without changing the
    /// raw-output fingerprint path above.
    fn module_graph_output(
        &self,
    ) -> Result<(Option<Output>, Option<ModuleToolchainRegistrations>)> {
        if !self.use_cquery && self.static_toolchain_scope_matches() {
            if let Some(output) = self.optional_toolchain_response(&[
                "mod",
                "graph",
                "--output=json",
                "--include_toolchain_registrations",
            ])? {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let complete = output.status.success() && !stderr.contains("ERROR:");
                let answered =
                    complete || extension_failure(&stderr).is_some_and(|failure| failure.answered);
                if answered {
                    if let Ok(graph) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                        if graph.get("key").and_then(serde_json::Value::as_str) == Some("<root>")
                            && graph
                                .get("dependencies")
                                .is_some_and(serde_json::Value::is_array)
                        {
                            let registrations = complete
                                .then(|| ModuleToolchainRegistrations::from_graph(&graph))
                                .flatten();
                            return Ok((Some(output), registrations));
                        }
                    }
                }
            }
        }
        let output = match self.run_capture(&["mod", "graph", "--output=json"]) {
            Ok(output) => Some(output),
            Err(error) => {
                self.check_cancelled()?;
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::Interrupted)
                {
                    return Err(error);
                }
                None
            }
        };
        self.check_cancelled()?;
        if output
            .as_ref()
            .is_some_and(|output| matches!(output.status.code(), None | Some(8)))
        {
            bail!("Bazel module graph acquisition was interrupted");
        }
        Ok((output, None))
    }

    /// This is a graph-mode choice for the whole ordinary query. A missing
    /// individual declaration or rule never changes how other edges are hashed.
    fn uses_declared_types(&self) -> bool {
        self.command_options
            .iter()
            .rev()
            .find_map(|option| {
                let (flag, value) = option.split_once('=').unwrap_or((option, "true"));
                match flag {
                    "--proto:possible_toolchain_types" => Some(
                        ["true", "t", "yes", "y", "1"]
                            .iter()
                            .any(|yes| value.eq_ignore_ascii_case(yes)),
                    ),
                    "--noproto:possible_toolchain_types" => Some(false),
                    _ => None,
                }
            })
            .unwrap_or(false)
    }

    fn with_possible_toolchain_types(&self, registrations: bool) -> Result<Self> {
        let mut options = self.clone();
        if !registrations
            || self.use_cquery
            || self.command_options.iter().any(|option| {
                option.starts_with("--proto:possible_toolchain_types")
                    || option.starts_with("--noproto:possible_toolchain_types")
            })
        {
            return Ok(options);
        }
        if self
            .optional_toolchain_output(&[
                "query",
                "set()",
                "--output=streamed_proto",
                "--proto:possible_toolchain_types",
            ])?
            .is_some()
        {
            options
                .command_options
                .push("--proto:possible_toolchain_types".into());
        }
        Ok(options)
    }

    /// `bazel mod graph --output=json`. The module graph proper survives a module extension
    /// Bazel cannot evaluate: the whole graph is printed before the extension is reported and
    /// the command exits 2.
    fn module_graph_json_tolerating(
        &self,
        output: Option<Output>,
        failed: &mut FailedExtensions,
    ) -> Result<(String, bool)> {
        let output = match output {
            Some(output) => output,
            None => self.run_capture(&["mod", "graph", "--output=json"])?,
        };
        let complete = output.status.success();
        let stdout = self.accept_mod_output(output, "graph --output=json", failed)?;
        let json = if self.isolated_dependency_root.is_some() {
            String::from_utf8(stdout).context("module graph is not valid UTF-8")?
        } else {
            String::from_utf8_lossy(&stdout).into_owned()
        };
        Ok((json.trim().to_owned(), complete))
    }

    pub fn dependency_fingerprint(&self) -> Result<String> {
        const STREAMED_VERSION: &str = "bzlmod-streamed-proto-v2";
        const TEXT_FALLBACK_VERSION: &str = "bzlmod-show-repo-text-v1";
        let total_start = Instant::now();
        let mut hasher = Sha256::new();
        if !self.is_bzlmod_enabled() {
            hasher.update(b"mode:legacy");
            eprintln!(
                "[BD-DBG][fingerprint-ms] mode=legacy version={TEXT_FALLBACK_VERSION} mapping=0 show_repo=0 total={}",
                total_start.elapsed().as_millis()
            );
            return Ok(hex::encode(hasher.finalize()));
        }

        hasher.update(b"mode:bzlmod\0");
        // Bind the guard to the registration data used by generation. Bazel builds can
        // report the same release and ordinary module graph but emit different query fields.
        let (graph, registrations) = self.module_graph_output()?;
        let module_graph = graph
            .and_then(Self::answered_module_graph)
            .unwrap_or_default();
        hasher.update(module_graph.as_bytes());
        hasher.update(b"\0");
        if registrations.is_some() {
            hasher.update(b"completeModuleToolchainRegistrations\0");
            if self
                .with_possible_toolchain_types(true)?
                .uses_declared_types()
            {
                hasher.update(b"directStaticToolchainInputs=5\0");
            }
        }

        let mapping_start = Instant::now();
        let canonical_names = self.canonical_bzlmod_repo_names()?;
        let mapping_millis = mapping_start.elapsed().as_millis();

        let show_repo_start = Instant::now();
        let streamed = self.show_repo_streamed_proto(&canonical_names);
        let show_repo_millis = show_repo_start.elapsed().as_millis();
        if let Ok(repo_state) = streamed {
            hasher.update(&repo_state);
            eprintln!(
                "[BD-DBG][fingerprint-ms] mode=bzlmod version={STREAMED_VERSION} mapping={mapping_millis} show_repo={show_repo_millis} total={} repoCount={} fallback=false",
                total_start.elapsed().as_millis(),
                canonical_names.len(),
            );
            return Ok(hex::encode(hasher.finalize()));
        }

        let fallback_show_repo_start = Instant::now();
        let repo_state = self.show_repo_fingerprint_text_fallback(&canonical_names)?;
        let fallback_show_repo_millis = fallback_show_repo_start.elapsed().as_millis();
        hasher.update(repo_state.as_bytes());
        eprintln!(
            "[BD-DBG][fingerprint-ms] mode=bzlmod version={TEXT_FALLBACK_VERSION} mapping={mapping_millis} show_repo={fallback_show_repo_millis} total={} repoCount={} fallback=true",
            total_start.elapsed().as_millis(),
            canonical_names.len(),
        );
        Ok(hex::encode(hasher.finalize()))
    }

    /// Asks Bazel for its release, output base and Starlark semantics in one invocation. `None`
    /// when the call fails (an older Bazel without one of the keys, say), so callers fall back to
    /// the separate calls they made before.
    ///
    /// The call carries the startup options and bazelrc the query will use but not
    /// `--bazelCommandOptions`, which are `bazel query` flags `bazel info` may reject.
    fn server_info(&self) -> Option<ServerInfo> {
        let output = self
            .run_capture(&["info", "release", "output_base", "starlark-semantics"])
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let mut info = parse_server_info(&String::from_utf8_lossy(&output.stdout))?;
        // `bazel info` reads the `common`, `build` and `info` sections of a bazelrc and
        // `bazel query` the `common` and `query` ones, and the query alone gets
        // `--bazelCommandOptions`. Leave the question open unless neither can set the flag.
        if info.external_package.is_some()
            && (self
                .command_options
                .iter()
                .any(|option| option.contains(WORKSPACE_FLAG))
                || self.bazelrc_mentions(WORKSPACE_FLAG))
        {
            info.external_package = None;
        }
        Some(info)
    }

    /// Whether any bazelrc Bazel reads for this workspace, or one they import, names `flag`.
    /// Deliberately coarse: a comment or an unrelated config naming it also counts.
    fn bazelrc_mentions(&self, flag: &str) -> bool {
        if self.no_bazelrc {
            return false;
        }
        let mut pending = vec![
            self.workspace.join(".bazelrc"),
            PathBuf::from("/etc/bazel.bazelrc"),
        ];
        if let Some(home) = std::env::var_os("HOME") {
            pending.push(PathBuf::from(home).join(".bazelrc"));
        }
        pending.extend(
            self.startup_options
                .iter()
                .filter_map(|option| option.strip_prefix("--bazelrc="))
                .map(PathBuf::from),
        );
        let mut seen = HashSet::new();
        while let Some(path) = pending.pop() {
            if seen.len() > 64 || !seen.insert(path.clone()) {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            if text.contains(flag) {
                return true;
            }
            for line in text.lines() {
                let line = line.trim();
                let Some(import) = line
                    .strip_prefix("try-import")
                    .or_else(|| line.strip_prefix("import"))
                else {
                    continue;
                };
                let import = import
                    .trim()
                    .replace("%workspace%", &self.workspace.to_string_lossy());
                let import = PathBuf::from(import);
                pending.push(if import.is_relative() {
                    self.workspace.join(import)
                } else {
                    import
                });
            }
        }
        false
    }

    fn version(&self) -> Result<BazelVersion> {
        let output = self.run_capture(&["version"])?;
        if !output.status.success() {
            bail!("Bazel version command failed, exit code {}", output.status);
        }
        let text = String::from_utf8_lossy(&output.stdout);
        parse_bazel_version(&text)
            .ok_or_else(|| anyhow!("Bazel version command returned unexpected output: {text}"))
    }

    fn with_exclude_filter(&self, query: String) -> String {
        self.exclude_targets_query
            .as_ref()
            .filter(|query| !query.trim().is_empty())
            .map_or(query.clone(), |exclude| {
                format!("({query}) except ({exclude})")
            })
    }

    #[cfg(test)]
    pub(crate) fn query_all_targets(&self) -> Result<Vec<Target>> {
        self.check_raw_targets_supported()?;
        Ok(self
            .query_all_targets_with(materialize_repository_inputs_for_batch, None)?
            .targets)
    }

    #[cfg(test)]
    pub(crate) fn check_raw_targets_supported(&self) -> Result<()> {
        if self.isolated_dependency_root.is_some() {
            bail!("--isolatedDependencyRoot requires generate_hashes to retain repository inputs");
        }
        Ok(())
    }

    pub(crate) fn query_all_targets_with(
        &self,
        mut transform: impl FnMut(&mut [Target], Option<RepositoryInputs>),
        native_definition: Option<NativeDefinitionRecorder<'_>>,
    ) -> Result<QueriedTargets> {
        if let Some(root) = &self.isolated_dependency_root {
            if self.use_cquery {
                bail!("--isolatedDependencyRoot={root} requires ordinary query");
            }
        }
        let mut bzlmod = BzlmodRepos::default();
        let server_info = self.server_info().unwrap_or_default();
        let checked_version = match server_info.version {
            Some(version) => Ok(version),
            None => self.version(),
        };
        let supports_bzlmod = checked_version
            .as_ref()
            .is_ok_and(|found| *found >= BazelVersion(8, 6, 0) && *found != BazelVersion(9, 0, 0));
        let mut survey = ModuleSurvey::default();
        let (bzlmod_enabled, root_mapping) =
            self.probe_query_repositories(supports_bzlmod, &mut survey)?;
        let version = match checked_version {
            Ok(found) => Some(found),
            Err(error) => {
                if let Some(root) = &self.isolated_dependency_root {
                    return Err(error).with_context(|| {
                        format!(
                            "--isolatedDependencyRoot={root}: failed to determine Bazel version"
                        )
                    });
                }
                if bzlmod_enabled {
                    if !self.keep_going {
                        return Err(error);
                    }
                    eprintln!(
                        "[Warn] failed to check Bazel version for Bzlmod repositories: {error:#}"
                    );
                }
                None
            }
        };
        if let Some(root) = &self.isolated_dependency_root {
            if !supports_bzlmod {
                let BazelVersion(major, minor, patch) = version.expect("checked version");
                bail!("--isolatedDependencyRoot={root}: Bazel {major}.{minor}.{patch} does not support Bzlmod repository discovery");
            }
            if !bzlmod_enabled {
                bail!(
                    "--isolatedDependencyRoot={root}: Bzlmod repository discovery is unavailable"
                );
            }
        }
        if bzlmod_enabled && supports_bzlmod {
            let queried = self.query_bzlmod_repos(root_mapping, survey, &mut |target, inputs| {
                transform(std::slice::from_mut(target), inputs);
            });
            let queried = if let Some(root) = &self.isolated_dependency_root {
                queried.with_context(|| format!("--isolatedDependencyRoot={root}"))
            } else {
                queried
            };
            match queried {
                Ok(repos) => bzlmod = repos,
                Err(error) if self.keep_going && self.isolated_dependency_root.is_none() => {
                    eprintln!("[Warn] failed to hash Bzlmod repositories: {error:#}");
                }
                Err(error) => return Err(error),
            }
        }
        let BzlmodRepos {
            targets: bzlmod_repos,
            shown_repositories,
            mut failed_extensions,
            canonical_to_apparent,
            module_graph_json,
            root_mapping,
            toolchain_registrations,
            scope,
        } = bzlmod;
        let querying = self.with_possible_toolchain_types(toolchain_registrations.is_some())?;
        let direct_suppliers = toolchain_registrations.is_some() && querying.uses_declared_types();
        let mapping = root_mapping
            .as_deref()
            .map(|raw| crate::hash::parse_apparent_repo_mapping(&String::from_utf8_lossy(raw)))
            .unwrap_or_default();
        let fallbacks = repository_fallbacks(&bzlmod_repos, &self.fine_grained_external_repos);
        let observe_stock_classes = !direct_suppliers
            && native_definition.is_some()
            && querying.can_use_observed_inputs()
            && !fallbacks.is_empty()
            && root_mapping.is_some()
            && version.is_some_and(|version| version >= BazelVersion(8, 0, 0));
        let mut transform = |batch: &mut [Target], inputs| {
            if !self.use_cquery && !direct_suppliers {
                batch.iter_mut().for_each(add_legacy_toolchain_inputs);
            }
            transform(batch, inputs);
        };
        let strict = (!scope.members.is_empty()).then(|| Self {
            keep_going: false,
            ..querying.clone()
        });
        let mut loads = BTreeMap::new();
        let mut targets = self.collect_all_targets(
            bzlmod_repos,
            server_info.external_package,
            |expression, use_cquery| {
                if let Some(strict) = &strict {
                    strict.query_with(
                        &self.with_exclude_filter(scope.expression(expression)),
                        false,
                        version,
                        &mut |batch| {
                            scope.record_build_loads(batch, &mut loads);
                            transform(batch, None);
                        },
                    )
                } else {
                    querying
                        .query_with_filtered_status(
                            expression,
                            use_cquery,
                            version,
                            &mut |batch| transform(batch, None),
                            |_| true,
                            observe_stock_classes,
                        )
                        .map(|(rows, _)| rows)
                }
            },
        )?;
        let stock_classes = if observe_stock_classes {
            take_stock_rule_classes(&mut targets, &mapping)
        } else {
            BTreeMap::new()
        };
        if let Some(strict) = &strict {
            // Direct users may name a target the hub doesn't export. Ask only about
            // edges actually seen in the ordinary graph, and keep the primary's rows.
            let mut coverage = ScopedCoverage::default();
            coverage.record(&scope, &targets);
            let mut additions = Vec::new();
            if !coverage.missing.is_empty() {
                let roots = query_labels(coverage.missing.iter())?;
                additions.push(format!(
                    "(let direct = deps({roots}) in $direct + buildfiles($direct))"
                ));
            }
            let readers: BTreeSet<_> = loads
                .iter()
                .filter(|(_, names)| {
                    names
                        .iter()
                        .filter_map(|name| scope.canonical(name))
                        .any(|name| !coverage.files.contains(&name))
                })
                .map(|(build, _)| build)
                .collect();
            if !readers.is_empty() {
                additions.push(format!(
                    "buildfiles({})",
                    query_labels(readers.into_iter())?
                ));
            }
            if !additions.is_empty() {
                let query = self.with_exclude_filter(additions.join(" + "));
                let mut extra = strict.query_with(&query, false, version, &mut |batch| {
                    scope.record_build_loads(batch, &mut loads);
                })?;
                retain_supplemental_targets(&mut extra, &targets);
                transform(&mut extra, None);
                coverage.record(&scope, &extra);
                targets.extend(extra);
                if let Some(missing) = coverage.missing.first() {
                    bail!("--isolatedDependencyRoot: scoped input {missing} was not returned");
                }
            }
            scope.connect_external_readers(&loads, &mut targets, &coverage)?;
        }
        if !self.use_cquery
            && !self.fine_grained_external_repos.is_empty()
            && self.isolated_dependency_root.is_none()
        {
            if let Err(error) = querying.acquire_alias_inputs(
                &mut targets,
                root_mapping.as_deref(),
                version,
                &mut transform,
            ) {
                self.check_cancelled()?;
                if !self.keep_going {
                    return Err(error).context("failed to acquire ordinary alias inputs");
                }
                eprintln!("[Warn] keeping ordinary repository fallbacks for incomplete alias discovery: {error:#}");
            }
        }
        let mut supplier_reads = SupplierReads::default();
        let mut read_context = RepositoryReadContext {
            mapping: &mapping,
            reads: &mut supplier_reads,
            native_rules: BTreeMap::new(),
        };
        match version {
            Some(version)
                if !fallbacks.is_empty()
                    && root_mapping.is_some()
                    && self.isolated_dependency_root.is_none()
                    && version >= BazelVersion(8, 0, 0)
                    && self
                        .exclude_targets_query
                        .as_deref()
                        .is_none_or(|exclude| exclude.trim().is_empty()) =>
            {
                match querying.acquire_repository_targets(
                    &mut targets,
                    &fallbacks,
                    (!self.use_cquery && querying.static_toolchain_scope_matches())
                        .then_some(&shown_repositories),
                    &mut read_context,
                    version,
                    &mut transform,
                ) {
                    Ok(()) => {}
                    Err(error)
                        if error
                            .downcast_ref::<QueryFailure>()
                            .is_some_and(|failure| matches!(failure.code, Some(3 | 7))) =>
                    {
                        self.check_cancelled()?;
                        eprintln!("[Warn] keeping repository fallbacks for unresolved ordinary inputs: {error:#}");
                    }
                    Err(error) => return Err(error),
                }
                if !stock_classes.is_empty() {
                    querying.add_unreported_query_inputs(
                        &mut targets,
                        &mapping,
                        &stock_classes,
                        &mut *read_context.reads,
                        version,
                    )?;
                }
            }
            _ => {}
        };
        let mut static_toolchains = None;
        if let Some(registrations) = toolchain_registrations
            .as_ref()
            .filter(|_| direct_suppliers)
        {
            let required = |targets: &[Target]| {
                targets
                    .iter()
                    .filter_map(|target| target.rule.as_option())
                    .filter_map(|rule| rule.possible_toolchain_types.as_option())
                    .flat_map(|types| &types.label)
                    .map(|label| canonical_query_label(label, &mapping).into_owned())
                    .collect::<BTreeSet<_>>()
            };
            let mut known_types = required(&targets);
            loop {
                let Some(metadata) =
                    querying.static_toolchains(&targets, registrations, &mapping, version)?
                else {
                    static_toolchains = None;
                    break;
                };
                querying.acquire_static_toolchain_targets(
                    &mut targets,
                    &metadata,
                    &fallbacks,
                    &mut read_context,
                    version,
                    &mut transform,
                )?;
                let next_types = required(&targets);
                static_toolchains = Some(metadata);
                if next_types == known_types {
                    break;
                }
                known_types = next_types;
            }
        }
        if let Some(record) = native_definition {
            querying.record_native_definitions(&targets, &mut read_context, record)?;
        }
        self.check_failed_extension_references(
            &targets,
            &mut failed_extensions,
            &canonical_to_apparent,
        )?;
        Ok(QueriedTargets {
            direct_toolchain_inputs: direct_suppliers,
            targets,
            module_graph_json,
            root_mapping,
            static_toolchains,
            output_base: server_info.output_base,
            scoped_sources: ScopedSources {
                repositories: scope
                    .aliases
                    .into_iter()
                    .filter_map(|(alias, canonical)| {
                        scope.members.contains(&canonical).then_some(alias)
                    })
                    .chain(scope.members.iter().cloned())
                    .collect(),
                repository_inputs: scope.repository_inputs,
                queried_files: HashSet::new(),
                supplier_reads: Some(supplier_reads),
            },
        })
    }

    fn acquire_repository_targets(
        &self,
        targets: &mut Vec<Target>,
        fallbacks: &HashMap<String, String>,
        shown_repositories: Option<&BTreeSet<String>>,
        context: &mut RepositoryReadContext<'_>,
        version: BazelVersion,
        transform: &mut impl FnMut(&mut [Target], Option<RepositoryInputs>),
    ) -> Result<()> {
        let mut roots = BTreeSet::new();
        for row in targets.iter() {
            let Some(rule) = row.rule.as_option() else {
                continue;
            };
            if !matches!(rule.rule_class.as_str(), "alias" | "filegroup")
                || main_repo_label_key(&rule.name).starts_with("//external:")
            {
                continue;
            }
            let mut observed = false;
            for input in
                target_inputs(row).filter(|label| repository_fallback(label, fallbacks).is_some())
            {
                roots.insert(input.clone());
                observed = true;
            }
            if observed {
                context.candidate_native(&rule.name);
            }
        }
        match self.acquire_repository_roots(
            targets,
            context,
            version,
            roots,
            RepositoryTraversal::Ordinary,
            transform,
        ) {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<QueryFailure>()
                    .is_some_and(|failure| matches!(failure.code, Some(3 | 7))) =>
            {
                self.check_cancelled()?;
                eprintln!(
                    "[Warn] keeping repository fallbacks for unresolved ordinary inputs: {error:#}"
                );
            }
            Err(error) => return Err(error),
        }
        if let Some(shown) = shown_repositories.filter(|repos| !repos.is_empty()) {
            self.acquire_literal_filegroup_readers(
                targets, fallbacks, shown, context, version, transform,
            )?;
        }
        Ok(())
    }

    /// Follow verified literal native forwarders from a filegroup input when Bazel
    /// already reported its exact repository. The ordinary collector above remains
    /// independent of this additional lookup.
    fn acquire_literal_filegroup_readers(
        &self,
        targets: &mut Vec<Target>,
        fallbacks: &HashMap<String, String>,
        shown_repositories: &BTreeSet<String>,
        context: &mut RepositoryReadContext<'_>,
        version: BazelVersion,
        transform: &mut impl FnMut(&mut [Target], Option<RepositoryInputs>),
    ) -> Result<()> {
        use crate::proto::blaze_query::attribute::Discriminator;
        let mapping = context.mapping;
        let mut referenced = BTreeMap::<String, BTreeSet<String>>::new();
        let mut missing = BTreeSet::new();
        for rule in targets.iter().filter_map(|row| row.rule.as_option()) {
            if rule.rule_class != "filegroup"
                || main_repo_label_key(&rule.name).starts_with("//external:")
            {
                continue;
            }
            let mut candidates = BTreeSet::new();
            for input in &rule.rule_input {
                if repository_fallback(input, fallbacks).is_some() {
                    continue;
                }
                let label = canonical_query_label(input, mapping);
                let Some((repo, _)) = label
                    .strip_prefix("@@")
                    .and_then(|label| label.split_once("//"))
                else {
                    continue;
                };
                if repo.is_empty() || !shown_repositories.contains(repo) {
                    continue;
                }
                let label = label.into_owned();
                missing.insert(label.clone());
                candidates.insert(label);
            }
            if !candidates.is_empty() {
                referenced
                    .entry(canonical_query_label(&rule.name, mapping).into_owned())
                    .or_default()
                    .extend(candidates);
            }
        }
        for name in targets.iter().filter_map(target_name) {
            missing.remove(canonical_query_label(name, mapping).as_ref());
        }
        if missing.is_empty() {
            return Ok(());
        }
        let referrers: BTreeSet<String> = referenced
            .iter()
            .filter(|(_, inputs)| inputs.iter().any(|input| missing.contains(input)))
            .map(|(name, _)| name.clone())
            .collect();
        for name in &referrers {
            context.candidate_native(name);
        }
        let mut roots = BTreeSet::new();
        let records = self.structural_rules(&referrers)?;
        let answered: BTreeSet<_> = records
            .keys()
            .map(|name| canonical_query_label(name, mapping).into_owned())
            .collect();
        for parent in referrers.difference(&answered) {
            context.reads.incomplete.insert(parent.clone());
            if let Some(inputs) = referenced.get(parent) {
                context
                    .reads
                    .deferred_bindings
                    .entry(parent.clone())
                    .or_default()
                    .extend(inputs.iter().cloned());
            }
        }
        for rule in records.into_values() {
            if rule.rule_class != "filegroup" || rule.rule_class_key.as_deref() != Some("filegroup")
            {
                continue;
            }
            context.observed_native(&rule.name);
            let id = canonical_query_label(&rule.name, mapping);
            let Some(expected) = referenced.get(id.as_ref()) else {
                continue;
            };
            let Some(srcs) = rule.attribute.iter().find(|attribute| {
                attribute.name == "srcs"
                    && attribute.r#type == Discriminator::LabelList
                    && attribute.selector_list.as_option().is_none()
            }) else {
                context.defer_binding(&rule, rule.attribute.iter().find(|a| a.name == "srcs"));
                continue;
            };
            let ordinary = rule
                .rule_input
                .iter()
                .map(|input| canonical_query_label(input, mapping).into_owned())
                .collect::<HashSet<_>>();
            for label in &srcs.string_list_value {
                let id = canonical_query_label(label, mapping);
                if expected.contains(id.as_ref())
                    && missing.contains(id.as_ref())
                    && ordinary.contains(id.as_ref())
                {
                    roots.insert(id.into_owned());
                }
            }
        }
        if roots.is_empty() {
            return Ok(());
        }
        self.acquire_repository_roots(
            targets,
            context,
            version,
            roots,
            RepositoryTraversal::ReaderLiterals(shown_repositories),
            transform,
        )
    }

    fn acquire_repository_roots(
        &self,
        targets: &mut Vec<Target>,
        context: &mut RepositoryReadContext<'_>,
        version: BazelVersion,
        roots: BTreeSet<String>,
        traversal: RepositoryTraversal<'_>,
        transform: &mut impl FnMut(&mut [Target], Option<RepositoryInputs>),
    ) -> Result<()> {
        use crate::proto::blaze_query::attribute::Discriminator;
        let mapping = context.mapping;
        if roots.is_empty() {
            return Ok(());
        }

        let primary: HashMap<_, _> = targets
            .iter()
            .enumerate()
            .filter_map(|(i, row)| Some((canonical_query_label(target_name(row)?, mapping), i)))
            .collect();
        // A condition can depend on a configurable flag or forwarding alias. A branch
        // in another, unseen repository stays unresolved rather than triggering a fetch.
        let represented: HashSet<_> = if traversal == RepositoryTraversal::Conditions {
            primary
                .keys()
                .filter(|label| !main_repo_label_key(label).starts_with("//external:"))
                .filter_map(|label| label.split_once("//").map(|(repo, _)| repo))
                .collect()
        } else {
            HashSet::new()
        };
        let mut probe = self.clone();
        probe.keep_going = true;
        probe.command_options.extend([
            "--keep_going".into(),
            "--proto:rule_classes".into(),
            "--proto:rule_inputs_and_outputs".into(),
        ]);
        let mut visited = HashSet::new();
        // Keep the initial ordinary roots separate from later forwarding steps.
        // The original ordinary input set may include configurable alternatives.
        let initial_roots: HashSet<_> = if traversal == RepositoryTraversal::Ordinary {
            roots
                .iter()
                .map(|label| canonical_query_label(label, mapping).into_owned())
                .collect()
        } else {
            HashSet::new()
        };
        let mut pending = roots;
        if traversal == RepositoryTraversal::ProviderLiterals {
            // A literal registration can name an installed SDK for every platform.
            // Start only in packages represented by this query's actual targets.
            let mut absent: HashSet<String> = pending
                .iter()
                .filter_map(|label| {
                    canonical_query_label(label, mapping)
                        .rsplit_once(':')
                        .map(|(package, _)| package.to_owned())
                })
                .collect();
            for label in primary.keys() {
                if let Some((package, _)) = label.rsplit_once(':') {
                    absent.remove(package);
                }
                if absent.is_empty() {
                    break;
                }
            }
            pending.retain(|label| {
                canonical_query_label(label, mapping)
                    .rsplit_once(':')
                    .is_some_and(|(package, _)| !absent.contains(package))
            });
        }
        let mut bindings = BTreeMap::new();
        let mut fetched = Vec::new();
        let mut appended = 0;
        let mut filegroups = BTreeMap::new();
        let mut aliases = BTreeSet::new();
        // A complete ordinary artifact can end in a regular file, or pass through a
        // native alias or filegroup. Looking below any other rule cannot establish
        // that proof, and can download archives unrelated to the exported artifact.
        // An initial ordinary root or a verified literal path can expose a typed reader.
        // Retain its complete row without following arbitrary rule dependencies.
        while !pending.is_empty() {
            let mut missing = BTreeSet::new();
            for name in std::mem::take(&mut pending) {
                let id = canonical_query_label(&name, mapping).into_owned();
                if let RepositoryTraversal::ReaderLiterals(shown) = traversal {
                    let allowed = main_repo_label_key(&id).starts_with("//")
                        || id
                            .strip_prefix("@@")
                            .and_then(|label| label.split_once("//"))
                            .is_some_and(|(repo, _)| shown.contains(repo));
                    if !allowed {
                        continue;
                    }
                }
                if traversal == RepositoryTraversal::Conditions
                    && !id
                        .split_once("//")
                        .is_some_and(|(repo, _)| represented.contains(repo))
                {
                    continue;
                }
                if !visited.insert(id.clone()) {
                    continue;
                }
                if let Some(index) = primary.get(id.as_str()) {
                    let Some(rule) = targets[*index].rule.as_option() else {
                        continue;
                    };
                    match rule.rule_class_key.as_deref() {
                        _ if traversal.is_reader() => {
                            if !matches!(rule.rule_class.as_str(), "alias" | "filegroup")
                                && rule.possible_toolchain_types.as_option().is_some()
                            {
                                continue;
                            }
                        }
                        // Read the unflattened actual even if the primary projection
                        // has only the union of the alias's ordinary dependencies.
                        _ if traversal == RepositoryTraversal::ProviderLiterals => {
                            if rule.rule_class != "alias" {
                                continue;
                            }
                        }
                        Some(class)
                            if matches!(class, "alias" | "filegroup")
                                || is_condition_class(class) =>
                        {
                            context.observed_native(&rule.name);
                            if rule.rule_class_key.as_deref() == Some("filegroup") {
                                filegroups.insert(rule.name.clone(), *index);
                            }
                            pending.extend(rule.rule_input.iter().cloned());
                            continue;
                        }
                        None if matches!(rule.rule_class.as_str(), "alias" | "filegroup")
                            || is_condition_class(&rule.rule_class) => {}
                        _ => continue,
                    }
                }
                missing.insert(name);
            }
            if missing.is_empty() {
                continue;
            }
            // The apparent spelling may differ between a rule input and a returned
            // row. Bazel owns both spellings; unreturned labels retain their fallback.
            let expression = self.with_exclude_filter(query_set(&missing)?);
            let (rows, complete) = match probe.query_with_filtered_status(
                &expression,
                false,
                Some(version),
                &mut |_| {},
                |_| true,
                false,
            ) {
                Ok(answer) => answer,
                Err(error)
                    if traversal.is_reader()
                        && error
                            .downcast_ref::<QueryFailure>()
                            .is_some_and(|failure| matches!(failure.code, Some(3 | 7))) =>
                {
                    self.check_cancelled()?;
                    context.incomplete(&missing);
                    eprintln!("[Warn] keeping repository fallbacks for unresolved literal forwarders: {error:#}");
                    continue;
                }
                Err(error) => {
                    context.incomplete(&missing);
                    return Err(error);
                }
            };
            if !complete {
                context.incomplete(&missing);
            }
            if traversal.is_reader() && !complete {
                continue;
            }
            if traversal.is_literal() {
                let names = rows
                    .iter()
                    .filter_map(|row| row.rule.as_option())
                    .filter(|rule| rule.rule_class_key.as_deref() == Some("alias"))
                    .map(|rule| rule.name.clone())
                    .collect();
                let observed = match self.alias_actuals(&names, version) {
                    Ok(observed) => observed,
                    Err(error)
                        if traversal.is_reader()
                            && error
                                .downcast_ref::<QueryFailure>()
                                .is_some_and(|failure| matches!(failure.code, Some(3 | 7))) =>
                    {
                        self.check_cancelled()?;
                        eprintln!("[Warn] keeping repository fallbacks for unresolved literal aliases: {error:#}");
                        BTreeMap::new()
                    }
                    Err(error) => return Err(error),
                };
                context.incomplete(names.iter().filter(|name| !observed.contains_key(*name)));
                bindings.extend(observed);
            }
            let filegroup_records = if traversal.is_reader() {
                let names = rows
                    .iter()
                    .filter_map(|row| row.rule.as_option())
                    .filter(|rule| rule.rule_class_key.as_deref() == Some("filegroup"))
                    .map(|rule| rule.name.clone())
                    .collect();
                let records = self.structural_rules(&names)?;
                context.incomplete(names.iter().filter(|name| !records.contains_key(*name)));
                records
            } else {
                HashMap::new()
            };
            'row: for row in rows {
                let Some(name) = target_name(&row) else {
                    continue;
                };
                let id = canonical_query_label(name, mapping);
                let existing = primary.get(&id).copied();
                if let Some(rule) = row.rule.as_option().filter(|rule| {
                    rule.rule_class_key.as_deref().is_some_and(|key| {
                        key == rule.rule_class
                            && (matches!(
                                key,
                                "alias" | "filegroup" | "toolchain" | "toolchain_type"
                            ) || is_condition_class(key))
                    })
                }) {
                    context.observed_native(&rule.name);
                }
                if let Some(rule) = row.rule.as_option().filter(|rule| {
                    complete
                        && rule.possible_toolchain_types.as_option().is_none()
                        && !rule.rule_class_key.as_deref().is_some_and(|key| {
                            key == rule.rule_class
                                && (matches!(
                                    key,
                                    "alias"
                                        | "filegroup"
                                        | "toolchain"
                                        | "toolchain_type"
                                        | "package_group"
                                ) || is_condition_class(key))
                        })
                }) {
                    context
                        .reads
                        .untyped_leaves
                        .insert(canonical_query_label(&rule.name, mapping).into_owned());
                }
                let opaque_reader = complete
                    && (initial_roots.contains(id.as_ref()) || traversal.is_reader())
                    && row.rule.as_option().is_some_and(|rule| {
                        rule.possible_toolchain_types
                            .as_option()
                            .is_some_and(|types| !types.label.is_empty())
                            && !rule.rule_class_key.as_deref().is_some_and(|class| {
                                matches!(class, "alias" | "filegroup") || is_condition_class(class)
                            })
                    });
                if opaque_reader {
                    appended += usize::from(existing.is_none());
                    fetched.push((existing, row));
                    continue;
                }
                if let Some(rule) = row.rule.as_option() {
                    'binding: {
                        match rule.rule_class_key.as_deref() {
                            Some("alias") if traversal.is_literal() => {
                                let Some(actual) = bindings
                                    .get(&rule.name)
                                    .filter(|attr| attr.r#type == Discriminator::Label)
                                    .and_then(|attr| attr.string_value.as_deref())
                                else {
                                    context.defer_binding(rule, bindings.get(&rule.name));
                                    break 'binding;
                                };
                                let dest = canonical_query_label(actual, mapping);
                                if !rule
                                    .rule_input
                                    .iter()
                                    .any(|input| canonical_query_label(input, mapping) == dest)
                                {
                                    context.defer_binding(rule, None);
                                    break 'binding;
                                }
                                pending.insert(actual.to_owned());
                            }
                            Some("filegroup") if traversal.is_reader() => {
                                filegroups.insert(
                                    rule.name.clone(),
                                    existing.unwrap_or(targets.len() + appended),
                                );
                                let Some(record) = filegroup_records.get(&rule.name) else {
                                    context.defer_binding(rule, None);
                                    break 'binding;
                                };
                                if record.rule_class != "filegroup"
                                    || record.rule_class_key.as_deref() != Some("filegroup")
                                {
                                    context.defer_binding(rule, None);
                                    break 'binding;
                                }
                                let Some(srcs) = record.attribute.iter().find(|attribute| {
                                    attribute.name == "srcs"
                                        && attribute.r#type == Discriminator::LabelList
                                        && attribute.selector_list.as_option().is_none()
                                }) else {
                                    context.defer_binding(
                                        rule,
                                        record.attribute.iter().find(|a| a.name == "srcs"),
                                    );
                                    break 'binding;
                                };
                                let ordinary = rule
                                    .rule_input
                                    .iter()
                                    .map(|input| canonical_query_label(input, mapping).into_owned())
                                    .collect::<HashSet<_>>();
                                let fresh = record
                                    .rule_input
                                    .iter()
                                    .map(|input| canonical_query_label(input, mapping).into_owned())
                                    .collect::<HashSet<_>>();
                                if srcs.string_list_value.iter().any(|label| {
                                    let id = canonical_query_label(label, mapping);
                                    !ordinary.contains(id.as_ref()) || !fresh.contains(id.as_ref())
                                }) {
                                    context.defer_binding(rule, None);
                                    break 'binding;
                                }
                                pending.extend(srcs.string_list_value.iter().cloned());
                                bindings.insert(rule.name.clone(), srcs.clone());
                            }
                            _ if traversal.is_literal() => continue 'row,
                            Some("alias") => {
                                aliases.insert(rule.name.clone());
                            }
                            Some("filegroup") => {
                                filegroups.insert(
                                    rule.name.clone(),
                                    existing.unwrap_or(targets.len() + appended),
                                );
                            }
                            Some(class) if is_condition_class(class) => {}
                            _ => continue 'row,
                        }
                    }
                    if !traversal.is_literal() {
                        pending.extend(rule.rule_input.iter().cloned());
                    }
                } else if row.source_file.as_option().is_none() || existing.is_some() {
                    continue;
                }
                appended += usize::from(existing.is_none());
                fetched.push((existing, row));
            }
        }
        let observed = self.alias_actuals(&aliases, version).inspect_err(|_| {
            context.incomplete(&aliases);
        })?;
        context.incomplete(aliases.iter().filter(|name| !observed.contains_key(*name)));
        bindings.extend(observed);
        if aliases.iter().any(|name| !bindings.contains_key(name)) {
            bail!("Bazel did not return every observed forwarding alias binding");
        }
        // Acquire only the package definitions of positively reached filegroups.
        // buildfiles(set(...)) includes their BUILD and loaded .bzl files without
        // walking their target dependencies.
        let mut packages = BTreeMap::new();
        for name in filegroups.keys() {
            if let Some((package, _)) = name.rsplit_once(':') {
                packages
                    .entry(package.to_owned())
                    .or_insert_with(|| name.clone());
            }
        }
        let mut definitions = HashMap::new();
        if !packages.is_empty() {
            let expression =
                self.with_exclude_filter(format!("buildfiles({})", query_set(packages.values())?));
            let mut acquired: HashSet<_> = fetched
                .iter()
                .filter_map(|(_, row)| target_name(row))
                .map(|name| canonical_query_label(name, mapping).into_owned())
                .collect();
            let (rows, complete) = match probe.query_with_filtered_status(
                &expression,
                false,
                Some(version),
                &mut |_| {},
                |_| true,
                false,
            ) {
                Ok(answer) => answer,
                Err(error)
                    if traversal.is_reader()
                        && error
                            .downcast_ref::<QueryFailure>()
                            .is_some_and(|failure| matches!(failure.code, Some(3 | 7))) =>
                {
                    self.check_cancelled()?;
                    eprintln!("[Warn] keeping repository fallbacks for unresolved literal definitions: {error:#}");
                    (Vec::new(), false)
                }
                Err(error) => {
                    context.incomplete(filegroups.keys());
                    return Err(error);
                }
            };
            if !complete {
                context.incomplete(filegroups.keys());
            }
            for row in rows {
                let Some(source) = row.source_file.as_option() else {
                    continue;
                };
                if let Some((package, "BUILD" | "BUILD.bazel")) = source.name.rsplit_once(':') {
                    definitions.insert(
                        package.to_owned(),
                        std::iter::once(source.name.clone())
                            .chain(source.subinclude.iter().cloned())
                            .collect::<Vec<_>>(),
                    );
                }
                let id = canonical_query_label(&source.name, mapping);
                if !primary.contains_key(&id) && acquired.insert(id.into_owned()) {
                    fetched.push((None, row));
                }
            }
        }
        drop(primary);
        for (existing, mut row) in fetched {
            if let Some(rule) = row.rule.as_option_mut() {
                if let Some(binding) = bindings.remove(&rule.name) {
                    rule.attribute
                        .retain(|attribute| attribute.name != binding.name);
                    rule.attribute.push(binding);
                }
                if let Some(index) = existing {
                    rule.rule_input
                        .extend(target_inputs(&targets[index]).cloned());
                }
                rule.rule_input.sort_unstable();
                rule.rule_input.dedup();
            }
            transform(std::slice::from_mut(&mut row), None);
            if let Some(index) = existing {
                targets[index] = row;
            } else {
                targets.push(row);
            }
        }
        for (name, index) in filegroups {
            if let Some(loads) = name
                .rsplit_once(':')
                .and_then(|(package, _)| definitions.get(package))
            {
                let inputs = &mut targets[index].rule.as_option_mut().unwrap().rule_input;
                inputs.extend(loads.iter().cloned());
                inputs.sort_unstable();
                inputs.dedup();
            }
        }
        Ok(())
    }

    /// Acquire caller-projected rows for verified registration paths, their ordinary inputs
    /// and named implementations in repositories already reached by this query.
    fn acquire_static_toolchain_targets(
        &self,
        targets: &mut Vec<Target>,
        metadata: &StaticToolchains,
        fallbacks: &HashMap<String, String>,
        context: &mut RepositoryReadContext<'_>,
        version: Option<BazelVersion>,
        transform: &mut impl FnMut(&mut [Target], Option<RepositoryInputs>),
    ) -> Result<()> {
        let mapping = context.mapping;
        let canonical = |label: &str| canonical_query_label(label, mapping).into_owned();
        let mut chosen = BTreeSet::new();
        let mut candidates = BTreeSet::new();
        let mut bounded = BTreeSet::new();
        let mut declaration_inputs = metadata.local_setting_inputs.clone();
        for (ty, literals) in &metadata.by_type {
            chosen.extend(metadata.type_paths.get(ty).into_iter().flatten().cloned());
            for name in metadata.type_paths.get(ty).into_iter().flatten() {
                context.observed_native(name);
            }
            for literal in literals {
                let Some(path) = metadata.registration_path_for(ty, literal) else {
                    continue;
                };
                chosen.extend(path.aliases.iter().cloned());
                chosen.extend(path.declarations.iter().cloned());
                for name in path.aliases.iter().chain(&path.declarations) {
                    context.observed_native(name);
                }
                if metadata.unresolved.contains(ty) || metadata.unresolved.contains(literal) {
                    continue;
                }
                for label in &path.declarations {
                    if metadata.unresolved.contains(label) {
                        continue;
                    }
                    let Some(declaration) = metadata.declarations.get(label) else {
                        continue;
                    };
                    declaration_inputs.extend(
                        metadata
                            .nodep_settings
                            .get(label)
                            .into_iter()
                            .flatten()
                            .cloned(),
                    );
                    chosen.extend(
                        declaration
                            .ordinary_inputs
                            .iter()
                            .chain(metadata.nodep_settings.get(label).into_iter().flatten())
                            .filter(|input| {
                                crate::hash::label_package(input)
                                    == crate::hash::label_package(label)
                            })
                            .cloned(),
                    );
                    declaration_inputs.extend(
                        declaration
                            .ordinary_inputs
                            .iter()
                            .filter(|input| {
                                *input != &declaration.ty
                                    && !declaration.implementations.contains(*input)
                            })
                            .cloned(),
                    );
                    for implementation in declaration
                        .implementations
                        .iter()
                        .filter(|label| !label.starts_with("@@["))
                    {
                        candidates.insert(implementation.clone());
                        // Reading the declaration already reached its repository. Its tool
                        // may live in a different package in that same repository.
                        if implementation.split_once("//").is_some_and(|(repo, _)| {
                            label
                                .split_once("//")
                                .is_some_and(|(owner, _)| owner == repo)
                        }) {
                            bounded.insert(implementation.clone());
                        }
                    }
                }
            }
        }
        // A declaration can use a platform constraint in another package. Its ordinary
        // edge identifies the target; an observed package in that repository bounds fetching.
        let mut unrepresented: HashSet<_> = declaration_inputs
            .iter()
            .chain(&candidates)
            .filter_map(|label| label.split_once("//").map(|(repo, _)| repo))
            .collect();
        let mut conditions = BTreeSet::new();
        let mut existing = HashSet::new();
        for row in targets.iter() {
            let Some(name) = target_name(row) else {
                continue;
            };
            if main_repo_label_key(name).starts_with("//external:") {
                continue;
            }
            let name = canonical_query_label(name, mapping);
            if let Some((repo, _)) = name.split_once("//") {
                unrepresented.remove(repo);
            }
            if declaration_inputs.contains(name.as_ref()) {
                if row
                    .rule
                    .as_option()
                    .is_some_and(|rule| is_condition_class(&rule.rule_class))
                {
                    conditions.insert(name.to_string());
                }
            } else if !chosen.contains(name.as_ref()) && !candidates.contains(name.as_ref()) {
                continue;
            }
            existing.insert(name.into_owned());
        }
        let represented = |label: &str| {
            label
                .split_once("//")
                .is_some_and(|(repo, _)| !unrepresented.contains(repo))
        };
        chosen.extend(
            declaration_inputs
                .iter()
                .filter(|label| represented(label))
                .cloned(),
        );
        let implementations: BTreeSet<_> = candidates
            .iter()
            .filter(|label| bounded.contains(*label) || represented(label))
            .cloned()
            .collect();
        chosen.extend(implementations.iter().cloned());
        chosen.retain(|label| !existing.contains(label) || implementations.contains(label));
        let answer = self.exact_toolchain_rows(&chosen, version)?;
        if !answer.complete {
            context.incomplete(&chosen);
        }
        let mut roots = BTreeSet::new();
        for mut row in answer.rows {
            let Some(name) = target_name(&row).map(canonical) else {
                continue;
            };
            if !chosen.contains(&name) {
                continue;
            }
            if answer.complete
                && declaration_inputs.contains(&name)
                && row
                    .rule
                    .as_option()
                    .is_some_and(|rule| is_condition_class(&rule.rule_class))
            {
                conditions.insert(name.clone());
            }
            if answer.complete && implementations.contains(&name) {
                roots.extend(
                    target_inputs(&row)
                        .filter(|label| repository_fallback(label, fallbacks).is_some())
                        .cloned(),
                );
            }
            if existing.contains(&name) {
                continue;
            }
            transform(std::slice::from_mut(&mut row), None);
            targets.push(row);
        }
        let Some(version) = version else {
            return Ok(());
        };
        for (roots, traversal, kind) in [
            (conditions, RepositoryTraversal::Conditions, "condition"),
            (roots, RepositoryTraversal::ProviderLiterals, "provider"),
        ] {
            match self
                .acquire_repository_roots(targets, context, version, roots, traversal, transform)
            {
                Ok(()) => {}
                Err(error)
                    if error
                        .downcast_ref::<QueryFailure>()
                        .is_some_and(|failure| matches!(failure.code, Some(3 | 7))) =>
                {
                    self.check_cancelled()?;
                    eprintln!(
                        "[Warn] Keeping repository fallbacks for unresolved {kind} inputs: {error:#}"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Read only the structure of named declarations and type aliases. A declaration
    /// already in the ordinary graph still needs its NODEP binding when no reader
    /// requested its type (#619); it is not thereby a MODULE registration.
    pub(crate) fn static_toolchains(
        &self,
        targets: &[Target],
        registrations: &ModuleToolchainRegistrations,
        mapping: &HashMap<String, String>,
        version: Option<BazelVersion>,
    ) -> Result<Option<StaticToolchains>> {
        let mut graph = StaticToolchains::default();
        let canonical = |label: &str| canonical_query_label(label, mapping).into_owned();
        let rules = || targets.iter().filter_map(|target| target.rule.as_option());
        let mut typed = rules()
            .filter_map(|rule| rule.possible_toolchain_types.as_option())
            .peekable();
        if self.use_cquery || typed.peek().is_none() {
            return Ok(None);
        }
        let required: BTreeSet<_> = typed
            .flat_map(|types| types.label.iter().map(|t| canonical(t)))
            .collect();
        let mut pending: BTreeSet<_> = rules()
            .filter(|r| r.rule_class == "toolchain")
            .map(|r| canonical(&r.name))
            .collect();
        graph.registration_order = registrations
            .labels
            .iter()
            .map(|label| canonical(label))
            .collect();
        if !required.is_empty() {
            pending.extend(graph.registration_order.iter().cloned());
            pending.extend(required.iter().cloned());
        }
        let mut structural = self.clone();
        structural.command_options.extend([
            "--consistent_labels".into(),
            "--proto:rule_classes".into(),
            "--proto:rule_inputs_and_outputs".into(),
            "--noproto:flatten_selects".into(),
            "--proto:output_rule_attrs=toolchain_type,toolchain,actual,target_settings".into(),
        ]);
        let mut seen = BTreeSet::new();
        while !pending.is_empty() {
            let mut current = std::mem::take(&mut pending);
            current.retain(|label| seen.insert(label.clone()));
            if current.is_empty() {
                break;
            }
            let answer = structural.exact_toolchain_rows(&current, version)?;
            if !answer.complete {
                graph.unresolved.extend(current.iter().cloned());
            }
            for target in answer.rows {
                let Some(rule) = target.rule.as_option() else {
                    continue;
                };
                let name = canonical(&rule.name);
                if !current.contains(&name) {
                    continue;
                }
                let attr = |name| rule.attribute.iter().find(|a| a.name == name);
                match rule.rule_class_key.as_deref() {
                    Some("alias") => {
                        let Some(actual) = attr("actual") else {
                            continue;
                        };
                        let dest: Vec<_> = structural_labels(actual)
                            .filter(|s| !s.is_empty())
                            .map(|s| canonical(s))
                            .collect();
                        if dest.is_empty() {
                            continue;
                        }
                        pending.extend(dest.iter().cloned());
                        graph.aliases.insert(name.clone(), dest);
                        graph.bindings.insert(
                            name,
                            vec![("actual", Sha256::digest(actual.encode_to_vec()).into())],
                        );
                    }
                    Some("toolchain") => {
                        let Some(ty) = attr("toolchain_type")
                            .filter(|a| a.nodep != Some(true))
                            .and_then(|a| a.string_value.as_deref())
                            .filter(|s| !s.is_empty())
                        else {
                            continue;
                        };
                        let Some(binding) = attr("toolchain").filter(|a| a.nodep == Some(true))
                        else {
                            continue;
                        };
                        let ty = canonical(ty);
                        let implementations: BTreeSet<_> = structural_labels(binding)
                            .filter(|s| !s.is_empty())
                            .map(|s| canonical(s))
                            .collect();
                        if implementations.is_empty() {
                            continue;
                        }
                        if !required.is_empty() {
                            pending.insert(ty.clone());
                        }
                        let mut bindings = vec![
                            ("toolchain_type", Sha256::digest(ty.as_bytes()).into()),
                            ("toolchain", Sha256::digest(binding.encode_to_vec()).into()),
                        ];
                        if let Some(settings) = attr("target_settings") {
                            match declaration_target_settings(settings) {
                                Some(labels) => {
                                    if !labels.is_empty() {
                                        // The declaration owns the binding. On producers using
                                        // NODEP_LABEL_LIST the resolver reads the matcher content.
                                        bindings.push((
                                            "target_settings",
                                            Sha256::digest(settings.encode_to_vec()).into(),
                                        ));
                                        if settings.nodep == Some(true) {
                                            graph.nodep_settings.insert(
                                                name.clone(),
                                                labels.into_iter().map(canonical).collect(),
                                            );
                                        }
                                    }
                                }
                                None => {
                                    graph.unresolved.insert(name.clone());
                                }
                            }
                        }
                        graph.bindings.insert(name.clone(), bindings);
                        graph.declarations.insert(
                            name,
                            StaticToolchainDeclaration {
                                ty,
                                implementations,
                                ordinary_inputs: rule
                                    .rule_input
                                    .iter()
                                    .map(|label| canonical(label))
                                    .collect(),
                            },
                        );
                    }
                    Some("toolchain_type") => {
                        graph.native_types.insert(name);
                    }
                    _ => {}
                }
            }
        }
        graph.unresolved.extend(seen.into_iter().filter(|name| {
            !graph.native_types.contains(name)
                && !graph.aliases.contains_key(name)
                && !graph.declarations.contains_key(name)
        }));
        if !required.is_empty() {
            graph.index_types(&required);
            // The ordinary graph may omit a non-actionable child of a rule that
            // explicitly names a local declaration. Read only those missing
            // literals in embedded tools or packages the primary query returned.
            let registered: HashSet<_> = graph
                .registration_paths
                .values()
                .flat_map(|path| path.declarations.iter())
                .collect();
            let local: HashSet<_> = graph
                .declarations
                .keys()
                .filter(|label| !registered.contains(*label))
                .map(String::as_str)
                .collect();
            if !local.is_empty() {
                // Discover possible forwarding paths on ordinary rows already
                // returned. Submit only paths named by an actual referrer to
                // Bazel for native identity and unflattened actual bindings.
                let mut aliases = HashMap::new();
                let mut parents: HashMap<_, Vec<_>> = HashMap::new();
                for rule in rules().filter(|rule| rule.rule_class == "alias") {
                    let name = canonical(&rule.name);
                    for input in &rule.rule_input {
                        parents
                            .entry(canonical_query_label(input, mapping))
                            .or_default()
                            .push(name.clone());
                    }
                    aliases.insert(name, rule);
                }
                let mut possible = BTreeSet::new();
                let mut queue: Vec<_> = local.iter().map(|name| (*name).to_owned()).collect();
                while let Some(label) = queue.pop() {
                    for alias in parents.get(label.as_str()).into_iter().flatten() {
                        if possible.insert(alias.clone()) {
                            queue.push(alias.clone());
                        }
                    }
                }
                let mut candidates = BTreeSet::new();
                let mut referenced = Vec::new();
                for rule in
                    rules().filter(|rule| rule.possible_toolchain_types.as_option().is_some())
                {
                    let mut holder = false;
                    for input in &rule.rule_input {
                        let name = canonical_query_label(input, mapping);
                        if local.contains(name.as_ref()) {
                            holder = true;
                            if !graph.unresolved.contains(name.as_ref()) {
                                graph.local_setting_inputs.extend(
                                    graph
                                        .nodep_settings
                                        .get(name.as_ref())
                                        .into_iter()
                                        .flatten()
                                        .cloned(),
                                );
                            }
                        }
                        if possible.contains(name.as_ref()) {
                            holder = true;
                            referenced.push(name.into_owned());
                        }
                    }
                    if holder {
                        candidates.extend(rule.rule_input.iter().map(|label| canonical(label)));
                    }
                }
                let mut forwarding = BTreeMap::new();
                while let Some(name) = referenced.pop() {
                    if forwarding.contains_key(&name) {
                        continue;
                    }
                    let inputs: Vec<_> = aliases[&name]
                        .rule_input
                        .iter()
                        .map(|input| canonical(input))
                        .filter(|input| possible.contains(input) || local.contains(input.as_str()))
                        .collect();
                    referenced.extend(
                        inputs
                            .iter()
                            .filter(|input| possible.contains(*input))
                            .cloned(),
                    );
                    forwarding.insert(name, inputs);
                }
                if !candidates.is_empty() {
                    let packages: HashSet<_> = candidates
                        .iter()
                        .filter_map(|label| {
                            label
                                .rsplit_once(':')
                                .map(|(package, _)| package.to_owned())
                        })
                        .collect();
                    let mut represented = HashSet::new();
                    for row in targets.iter().filter_map(target_name) {
                        let label = canonical_query_label(row, mapping);
                        candidates.remove(label.as_ref());
                        if let Some((package, _)) = label.rsplit_once(':') {
                            if packages.contains(package) {
                                represented.insert(package.to_owned());
                            }
                        }
                    }
                    candidates.retain(|label| {
                        label.starts_with("@@bazel_tools//")
                            || label
                                .rsplit_once(':')
                                .is_some_and(|(package, _)| represented.contains(package))
                    });
                    forwarding.retain(|name, _| !graph.aliases.contains_key(name));
                    candidates.extend(forwarding.keys().cloned());
                    if !candidates.is_empty() {
                        let answer = structural.exact_toolchain_rows(&candidates, version)?;
                        if answer.complete {
                            for target in answer.rows {
                                let Some(name) = target_name(&target).map(canonical) else {
                                    continue;
                                };
                                if forwarding.contains_key(&name) {
                                    if let Some(rule) = target.rule.as_option() {
                                        match rule.rule_class_key.as_deref() {
                                            Some("alias") => {
                                                let destinations: Vec<_> = rule
                                                    .attribute
                                                    .iter()
                                                    .find(|attr| attr.name == "actual")
                                                    .into_iter()
                                                    .flat_map(structural_labels)
                                                    .filter(|label| !label.is_empty())
                                                    .map(|label| canonical(label))
                                                    .collect();
                                                if !destinations.is_empty() {
                                                    forwarding.remove(&name);
                                                    graph
                                                        .local_registration_aliases
                                                        .insert(name, destinations);
                                                }
                                            }
                                            Some(_) => {
                                                forwarding.remove(&name);
                                            }
                                            None => {}
                                        }
                                    }
                                    continue;
                                }
                                let native_group = target.rule.as_option().is_some_and(|rule| {
                                    rule.rule_class_key.as_deref() == Some("package_group")
                                });
                                if native_group
                                    || target.r#type == target::Discriminator::SourceFile
                                {
                                    if let Some(label) = target_name(&target) {
                                        graph.non_reader_inputs.insert(canonical(label));
                                    }
                                }
                            }
                        }
                        // A missing answer cannot prove a local binding.
                        // Retain the known declaration's old uncertainty on the
                        // referrer instead of discarding an ordinary path.
                        graph.unresolved.extend(forwarding.keys().cloned());
                        // A referenced registration can end at a local declaration through
                        // several aliases. The verified last hop carries its matcher labels.
                        for (alias, values) in &graph.local_registration_aliases {
                            if graph.unresolved.contains(alias) {
                                continue;
                            }
                            for value in values {
                                if local.contains(value.as_str())
                                    && !graph.unresolved.contains(value)
                                {
                                    graph.local_setting_inputs.extend(
                                        graph
                                            .nodep_settings
                                            .get(value)
                                            .into_iter()
                                            .flatten()
                                            .cloned(),
                                    );
                                }
                            }
                        }
                        graph.local_registration_aliases.extend(forwarding);
                    }
                }
            }
        }
        Ok(Some(graph))
    }

    /// An exact row read, in the caller's attribute projection unless the structural
    /// discovery above selected its own. Callers choose the bounded literal set to
    /// acquire, and may only rely on labels actually returned. No deps() traversal.
    pub(crate) fn exact_toolchain_rows(
        &self,
        labels: &BTreeSet<String>,
        version: Option<BazelVersion>,
    ) -> Result<LiteralToolchainRows> {
        let operands: BTreeSet<_> = labels
            .iter()
            .filter(|label| !label.starts_with("@@["))
            .cloned()
            .collect();
        if operands.is_empty() {
            return Ok(LiteralToolchainRows {
                rows: Vec::new(),
                complete: labels.is_empty(),
            });
        }
        let mut query = self.clone();
        query.keep_going = true;
        query.command_options.push("--keep_going".into());
        let expression = self.with_exclude_filter(query_set(&operands)?);
        match query.query_with_filtered_status(
            &expression,
            false,
            version,
            &mut |_| {},
            |_| true,
            false,
        ) {
            Ok((rows, complete)) => Ok(LiteralToolchainRows {
                rows,
                complete: complete && labels.len() == operands.len(),
            }),
            Err(error)
                if error
                    .downcast_ref::<QueryFailure>()
                    .is_some_and(|e| matches!(e.code, Some(3 | 7))) =>
            {
                self.check_cancelled()?;
                eprintln!("[Warn] Keeping unresolved toolchain inputs for an unavailable literal query: {error:#}");
                Ok(LiteralToolchainRows {
                    rows: Vec::new(),
                    complete: false,
                })
            }
            Err(error) => Err(error),
        }
    }

    /// A fine repository may expose libraries in other repositories through aliases. Follow
    /// actual targets of aliases used by the ordinary graph, without enrolling more namespaces.
    fn acquire_alias_inputs(
        &self,
        targets: &mut Vec<Target>,
        root_mapping: Option<&[u8]>,
        version: Option<BazelVersion>,
        transform: &mut impl FnMut(&mut [Target], Option<RepositoryInputs>),
    ) -> Result<()> {
        let mapping = root_mapping
            .map(|raw| crate::hash::parse_apparent_repo_mapping(&String::from_utf8_lossy(raw)))
            .unwrap_or_default();
        let fine: HashSet<_> = self
            .fine_grained_external_repos
            .iter()
            .map(|repo| {
                let name = repo.trim_start_matches('@');
                if repo.starts_with("@@") {
                    name
                } else {
                    mapping.get(name).map_or(name, String::as_str)
                }
            })
            .collect();
        let fine_target = |name: &str| {
            name.strip_prefix('@')
                .and_then(|name| name.split_once("//"))
                .is_some_and(|(repo, _)| {
                    let canonical = repo
                        .strip_prefix('@')
                        .unwrap_or_else(|| mapping.get(repo).map_or(repo, String::as_str));
                    fine.contains(canonical)
                })
        };
        let mut primary = HashSet::new();
        let mut inside = HashMap::new();
        let mut queue = Vec::new();
        for row in targets.iter() {
            let Some(name) = target_name(row) else {
                continue;
            };
            let id = canonical_query_label(name, &mapping);
            primary.insert(id.clone());
            if fine_target(name) {
                inside.insert(id, row);
            } else if !main_repo_label_key(name).starts_with("//external:") {
                queue.extend(target_inputs(row).filter(|s| fine_target(s)));
            }
        }
        let mut walked = HashSet::new();
        let mut aliases = BTreeSet::new();
        while let Some(input) = queue.pop() {
            let id = canonical_query_label(input, &mapping);
            if !walked.insert(id.clone()) {
                continue;
            }
            let Some(&row) = inside.get(&id) else {
                continue;
            };
            if let Some(rule) = row.rule.as_option().filter(|r| r.rule_class == "alias") {
                aliases.insert(rule.name.clone());
            }
            queue.extend(target_inputs(row).filter(|s| fine_target(s)));
        }
        if aliases.is_empty() {
            return Ok(());
        }
        let version = match version {
            Some(version) => version,
            None => self.version()?,
        };
        // Bazel 7 does not expose the native rule class identity needed to distinguish aliases.
        if version < BazelVersion(8, 0, 0) {
            return Ok(());
        }

        // The caller may exclude actual from the attributes it wants to hash. Inspect this
        // finite set separately; keep the original rows and their full select-condition inputs.
        let mut bindings = self.alias_actuals(&aliases, version)?;
        if bindings.is_empty() {
            return Ok(());
        }
        let mut missing = BTreeSet::new();
        for actual in bindings.values() {
            for destination in actual
                .string_value
                .iter()
                .chain(
                    actual
                        .selector_list
                        .as_option()
                        .into_iter()
                        .flat_map(|list| &list.elements)
                        .flat_map(|selector| &selector.entries)
                        .filter_map(|e| e.string_value.as_ref()),
                )
                .filter(|label| !label.is_empty())
            {
                if !primary.contains(&canonical_query_label(destination, &mapping)) {
                    missing.insert(destination.clone());
                }
            }
        }
        let mut strict = self.clone();
        strict.keep_going = false;
        strict
            .command_options
            .extend(["--nokeep_going".into(), "--proto:rule_classes".into()]);
        let extra = if missing.is_empty() {
            Vec::new()
        } else {
            let expression = self.with_exclude_filter(format!(
                "let needed = deps({}) in $needed + buildfiles($needed)",
                query_set(&missing)?
            ));
            strict.query_with_filtered(
                &expression,
                false,
                Some(version),
                &mut |batch| transform(batch, None),
                |row| {
                    target_name(row).is_some_and(|name| {
                        !primary.contains(&canonical_query_label(name, &mapping))
                    })
                },
            )?
        };
        let new_aliases = extra
            .iter()
            .filter_map(|target| target.rule.as_option())
            .filter(|r| r.rule_class_key.as_deref() == Some("alias"))
            .map(|r| r.name.clone())
            .collect();
        bindings.extend(self.alias_actuals(&new_aliases, version)?);
        // Primary and supplemental rows may have been prehashed, which releases their
        // projected attributes. Re-read only these native aliases with the original options,
        // then use their evaluated actual, including the mapping of select keys to labels.
        let mut aliases_with_attrs = strict.query_with(
            &self.with_exclude_filter(query_set(bindings.keys())?),
            false,
            Some(version),
            &mut |_| {},
        )?;
        let mut alias_attrs = HashMap::new();
        for row in &mut aliases_with_attrs {
            if let Some(rule) = row.rule.as_option_mut() {
                if let Some(actual) = bindings.remove(&rule.name) {
                    rule.attribute.retain(|attr| attr.name != "actual");
                    rule.attribute.push(actual);
                    alias_attrs.insert(rule.name.clone(), std::mem::take(&mut rule.attribute));
                }
            }
        }
        if !bindings.is_empty() {
            bail!("Bazel did not return all observed forwarding aliases");
        }
        let first = targets.len();
        targets.extend(extra);
        let mut definitions: HashMap<String, Vec<String>> = targets[first..]
            .iter()
            .filter_map(|row| row.rule.as_option().map(|r| &r.name))
            .filter_map(|name| name.rsplit_once(':'))
            .map(|(package, _)| (package.to_owned(), Vec::new()))
            .collect();
        for row in targets.iter() {
            let Some(source) = row.source_file.as_option() else {
                continue;
            };
            let Some((package, "BUILD" | "BUILD.bazel")) = source.name.rsplit_once(':') else {
                continue;
            };
            if let Some(inputs) = definitions.get_mut(package) {
                inputs.push(source.name.clone());
                inputs.extend(source.subinclude.iter().cloned());
                inputs.sort_unstable();
                inputs.dedup();
            }
        }
        for (index, row) in targets.iter_mut().enumerate() {
            let Some(rule) = row.rule.as_option_mut() else {
                continue;
            };
            if let Some(attrs) = alias_attrs.remove(&rule.name) {
                rule.attribute = attrs;
                // Hash the alias rule itself. A generated BUILD can define unrelated siblings.
                transform(std::slice::from_mut(row), None);
                continue;
            }
            if index < first {
                continue;
            }
            if let Some((package, _)) = rule.name.rsplit_once(':') {
                if let Some(loads) = definitions.get(package) {
                    rule.rule_input.extend(loads.iter().cloned());
                    rule.rule_input.sort_unstable();
                    rule.rule_input.dedup();
                }
            }
        }
        Ok(())
    }

    /// Supply the full native definitions used by acquisition to direct hashing.
    /// Only already-returned rules are requested. An unavailable definition stays
    /// an uncertainty on that rule and its observed inputs.
    fn record_native_definitions(
        &self,
        targets: &[Target],
        context: &mut RepositoryReadContext<'_>,
        record: NativeDefinitionRecorder<'_>,
    ) -> Result<()> {
        let mapping = context.mapping;
        let mut requested = BTreeMap::<String, bool>::new();
        for (name, observed) in &context.native_rules {
            requested
                .entry(canonical_query_label(name, mapping).into_owned())
                .and_modify(|known| *known |= *observed)
                .or_insert(*observed);
        }
        if requested.is_empty() {
            return Ok(());
        }
        let mut indexed = BTreeMap::<String, Vec<&Rule>>::new();
        for rule in targets.iter().filter_map(|target| target.rule.as_option()) {
            let id = canonical_query_label(&rule.name, mapping).into_owned();
            if requested.contains_key(&id) {
                indexed.entry(id).or_default().push(rule);
            }
        }
        context.incomplete(requested.keys().filter(|id| !indexed.contains_key(*id)));
        let labels = indexed.keys().cloned().collect();
        let mut returned = BTreeMap::new();
        let mut duplicates = BTreeSet::new();
        for rule in self.structural_rules(&labels)?.into_values() {
            let id = canonical_query_label(&rule.name, mapping).into_owned();
            if returned.insert(id.clone(), rule).is_some() {
                duplicates.insert(id);
            }
        }
        for (id, expected) in indexed {
            let actual = returned.get(&id).filter(|_| !duplicates.contains(&id));
            let native = actual.is_some_and(|rule| {
                rule.rule_class_key.as_deref().is_some_and(|key| {
                    key == rule.rule_class
                        && (matches!(key, "alias" | "filegroup" | "toolchain" | "toolchain_type")
                            || is_condition_class(key))
                })
            });
            if !requested[&id]
                && actual.is_some_and(|rule| rule.rule_class_key.is_some())
                && !native
            {
                continue;
            }
            for expected in expected {
                let inputs = expected
                    .rule_input
                    .iter()
                    .map(|input| canonical_query_label(input, mapping))
                    .collect::<HashSet<_>>();
                if let Some(actual) = actual.filter(|actual| {
                    native
                        && actual.rule_class == expected.rule_class
                        && actual
                            .rule_input
                            .iter()
                            .all(|input| inputs.contains(&canonical_query_label(input, mapping)))
                }) {
                    let mut definition = actual.clone();
                    definition.name = expected.name.clone();
                    record(&expected.name, &definition);
                    context.reads.verified_native.insert(id.clone());
                } else {
                    context.reads.incomplete.insert(id.clone());
                    context.reads.unrecorded_definitions.insert(id.clone());
                }
            }
        }
        Ok(())
    }

    /// Verify native forwarding roles and unflattened bindings on labels already in the
    /// caller's graph. This query does not add any targets to a raw hash request.
    fn structural_rules(&self, labels: &BTreeSet<String>) -> Result<HashMap<String, Rule>> {
        if labels.is_empty() {
            return Ok(HashMap::new());
        }
        let mut metadata = self.clone();
        metadata.keep_going = false;
        metadata.command_options.extend([
            "--nokeep_going".into(),
            "--proto:rule_classes".into(),
            "--proto:default_values".into(),
            "--proto:rule_inputs_and_outputs".into(),
            "--noproto:flatten_selects".into(),
            "--proto:output_rule_attrs=all".into(),
        ]);
        let rows = match metadata.query_with(
            &self.with_exclude_filter(query_set(labels)?),
            false,
            None,
            &mut |_| {},
        ) {
            Ok(rows) => rows,
            Err(error)
                if error
                    .downcast_ref::<QueryFailure>()
                    .is_some_and(|failure| matches!(failure.code, Some(3 | 7))) =>
            {
                self.check_cancelled()?;
                eprintln!("[Warn] retaining repository fallbacks for unresolved structural rules: {error:#}");
                return Ok(HashMap::new());
            }
            Err(error) => return Err(error),
        };
        Ok(rows
            .into_iter()
            .filter_map(|row| row.rule.into_option())
            .map(|rule| (rule.name.clone(), rule))
            .collect())
    }

    fn alias_actuals(
        &self,
        aliases: &BTreeSet<String>,
        version: BazelVersion,
    ) -> Result<BTreeMap<String, Attribute>> {
        if aliases.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut metadata = self.clone();
        metadata.keep_going = false;
        metadata.command_options.extend([
            "--nokeep_going".into(),
            "--proto:output_rule_attrs=actual".into(),
            "--proto:rule_classes".into(),
            "--noproto:flatten_selects".into(),
        ]);
        let records = metadata.query_with(
            &self.with_exclude_filter(query_set(aliases)?),
            false,
            Some(version),
            &mut |_| {},
        )?;
        Ok(records
            .into_iter()
            .filter_map(|target| {
                let rule = target.rule.into_option()?;
                if rule.rule_class_key.as_deref() != Some("alias") {
                    return None;
                }
                let actual = rule.attribute.into_iter().find(|a| a.name == "actual")?;
                Some((rule.name, actual))
            })
            .collect())
    }

    /// `external_package` is whether `//external` exists, when known; `Some(false)` leaves it out
    /// of the query instead of trying it and retrying without it.
    fn collect_all_targets(
        &self,
        bzlmod_repos: Vec<Target>,
        external_package: Option<bool>,
        mut query: impl FnMut(&str, bool) -> Result<Vec<Target>>,
    ) -> Result<Vec<Target>> {
        let include_external = !self.exclude_external_targets && external_package != Some(false);
        let mut queries = Vec::new();
        if include_external {
            queries.push("'//external:all-targets'".to_owned());
        }
        if self.use_cquery {
            let expression = self
                .cquery_expression
                .clone()
                .unwrap_or_else(|| "deps(//...:all-targets)".to_owned());
            let mut targets = query(&self.with_exclude_filter(expression), true)?;
            if include_external {
                match query("'//external:all-targets'", false) {
                    Ok(external) => targets.extend(external),
                    Err(error) if is_external_package_error(&error.to_string()) => {
                        eprintln!(
                            "[Warn] //external is not available; dropping //external:all-targets"
                        );
                    }
                    Err(error) => return Err(error),
                }
            }
            targets.extend(bzlmod_repos);
            deduplicate_targets(targets)
        } else {
            queries.push("'//...:all-targets'".to_owned());
            queries.extend(
                self.fine_grained_external_repos
                    .iter()
                    .map(|repo| format!("'{repo}//...:all-targets'")),
            );
            let full = self.with_exclude_filter(queries.join(" + "));
            match query(&full, false) {
                Ok(mut targets) => {
                    targets.extend(bzlmod_repos);
                    deduplicate_targets(targets)
                }
                Err(error) if include_external && is_external_package_error(&error.to_string()) => {
                    let without_external = self.with_exclude_filter(
                        std::iter::once("'//...:all-targets'".to_owned())
                            .chain(
                                self.fine_grained_external_repos
                                    .iter()
                                    .map(|repo| format!("'{repo}//...:all-targets'")),
                            )
                            .collect::<Vec<_>>()
                            .join(" + "),
                    );
                    let mut targets = query(&without_external, false)?;
                    targets.extend(bzlmod_repos);
                    deduplicate_targets(targets)
                }
                Err(error) => Err(error),
            }
        }
    }
    fn query_bzlmod_repos(
        &self,
        root_mapping: Option<Vec<u8>>,
        survey: ModuleSurvey,
        transform: &mut impl FnMut(&mut Target, Option<RepositoryInputs>),
    ) -> Result<BzlmodRepos> {
        let mut failed = FailedExtensions::default();
        // The initial probe returns stdout only on success. The fallback may be partial.
        let retain_root_mapping = root_mapping.is_some();
        let root_mapping = match root_mapping {
            Some(mapping) => mapping,
            None => {
                let output = self.run_capture(&["mod", "dump_repo_mapping", ""])?;
                self.accept_mod_output(output, "dump_repo_mapping", &mut failed)?
            }
        };
        let canonical_to_apparent = parse_repo_mapping(&String::from_utf8_lossy(&root_mapping));
        let (graph_output, toolchain_registrations) = match survey.graph {
            Some(output) => (Some(output), survey.toolchain_registrations),
            None => self.module_graph_output()?,
        };
        let (module_graph, complete_graph) =
            match self.module_graph_json_tolerating(graph_output, &mut failed) {
                Ok((json, complete)) => (Some(json), complete),
                Err(error) if self.keep_going && self.isolated_dependency_root.is_none() => {
                    eprintln!("[Warn] {error:#}; hashing Bzlmod repositories without module edges");
                    (None, false)
                }
                Err(error) => return Err(error),
            };
        let module_edges = module_graph
            .as_deref()
            .map(parse_module_dependency_edges)
            .unwrap_or_default();
        let mut canonical_names = canonical_to_apparent
            .keys()
            .filter(|name| name.contains('+') || name.contains('~'))
            .map(|name| format!("@@{name}"))
            .collect::<BTreeSet<_>>();
        // Modules the root does not declare (e.g. one only a dependency pulls in under its own
        // apparent name) are absent from the root's repo mapping, yet sit on the path between
        // root-visible repos. Ask for them by module key so that path stays connected (#510).
        let hidden_modules = module_graph
            .as_deref()
            .map(|json| {
                if self.isolated_dependency_root.is_some() && complete_graph {
                    isolated_module_repo_names(json, &canonical_to_apparent)
                } else {
                    Ok(hidden_module_repo_names(json, &canonical_to_apparent))
                }
            })
            .transpose()?;
        let hidden_modules = hidden_modules.unwrap_or_default();
        canonical_names.extend(hidden_modules.keys().cloned());
        // Repositories a module extension generates without any module importing them (a Go
        // SDK behind a toolchain, the crate behind a hub alias) are in no module's repo mapping,
        // so nothing above names them. Enumerate them from the extensions' own mappings (#522).
        let extension_repos = match self.extension_repositories(
            &canonical_to_apparent,
            hidden_modules.values().cloned().collect(),
            survey.mappings,
            retain_root_mapping && complete_graph,
            &mut failed,
        ) {
            Ok(repos) => repos,
            Err(error) if self.keep_going && self.isolated_dependency_root.is_none() => {
                eprintln!("[Warn] failed to enumerate module extension repositories: {error:#}");
                ExtensionRepositories::default()
            }
            Err(error) => return Err(error),
        };
        canonical_names.extend(
            extension_repos
                .generated
                .iter()
                .map(|name| format!("@@{name}")),
        );
        let repositories = if canonical_names.is_empty() {
            Vec::new()
        } else {
            self.show_repositories_within(
                &canonical_names.into_iter().collect::<Vec<_>>(),
                &mut failed,
                mod_argument_byte_budget(),
                || {
                    verified_hidden_modules(
                        module_graph.as_deref(),
                        &root_mapping,
                        &extension_repos.module_mappings,
                        &hidden_modules,
                    )
                    .then_some(&hidden_modules)
                },
            )?
        };
        let mut scope = IsolatedRepoScope::default();
        let label_only = LabelOnlyRepositories {
            extensions: self
                .label_only_extension_prefixes(&canonical_to_apparent, &extension_repos.generated),
            owner_exemptions: if let Some(root) = &self.isolated_dependency_root {
                if let Some(extension) = failed.extensions.first() {
                    bail!("module extension {extension} failed");
                }
                if let Some(repository) = failed.unavailable.first() {
                    bail!("repository mapping for {repository} failed");
                }
                if failed.observed {
                    bail!("Bazel reported an unidentified module extension failure");
                }
                if !retain_root_mapping {
                    bail!("root repository mapping is incomplete");
                }
                if !complete_graph {
                    bail!("module graph is incomplete");
                }
                if !extension_repos.complete_mappings {
                    bail!("repository mappings are incomplete");
                }
                scope =
                    resolve_isolated_root(root, &root_mapping, &extension_repos, &repositories)?;
                scope.members.clone()
            } else {
                BTreeSet::new()
            },
        };
        let shown_repositories = repositories
            .iter()
            .filter_map(|repository| repository.canonical_name.clone())
            .collect();
        let targets = lower_repositories(
            repositories,
            &canonical_to_apparent,
            &module_edges,
            // In query mode a toolchain is resolved, never declared, so the Go SDK repo behind
            // `go_sdk.download(patches = ...)` is on no target's input list and the module that
            // owns the extension stands in for it. cquery sees the resolved toolchain as a real
            // input, so there the nodes alone carry the change and the stand-in edges would only
            // widen the impacted set.
            (!self.use_cquery).then_some(&extension_repos.imported),
            &label_only,
            &self.workspace,
            transform,
        );
        Ok(BzlmodRepos {
            targets,
            shown_repositories,
            failed_extensions: failed,
            canonical_to_apparent,
            module_graph_json: module_graph,
            toolchain_registrations: if complete_graph {
                toolchain_registrations
            } else {
                None
            },
            root_mapping: retain_root_mapping.then_some(root_mapping),
            scope,
        })
    }

    /// The usage prefixes (`rules_rs++crate`) of `label_only_module_extensions`. An entry that
    /// does not parse, names a module the root cannot see, or matches no generated repository is
    /// reported and ignored, which leaves that extension on the conservative edges. So is one
    /// whose prefix Bazel may have given to another extension: two `.bzl` files of one module
    /// that export the same extension name are told apart only by a numeric suffix.
    fn label_only_extension_prefixes(
        &self,
        canonical_to_apparent: &BTreeMap<String, Vec<String>>,
        generated: &BTreeSet<String>,
    ) -> BTreeSet<String> {
        let prefixes_in_use = generated
            .iter()
            .filter_map(|repo| extension_usage_prefix(repo))
            .collect::<BTreeSet<_>>();
        let mut prefixes = BTreeSet::new();
        for id in &self.label_only_module_extensions {
            let parsed = id.rsplit_once('%').and_then(|(file, name)| {
                let (repo, _) = file.split_once("//")?;
                Some((repo, name))
            });
            let Some((repo, name)) = parsed.filter(|(_, name)| !name.is_empty()) else {
                eprintln!(
                    "[Warn] --labelOnlyModuleExtensions: {id} is not of the form @module//path.bzl%extension"
                );
                continue;
            };
            let canonical = match repo.strip_prefix("@@") {
                Some(canonical) => Some(canonical.to_owned()),
                None => {
                    let apparent = repo.trim_start_matches('@');
                    canonical_to_apparent
                        .iter()
                        .find(|(_, names)| names.iter().any(|name| name == apparent))
                        .map(|(canonical, _)| canonical.clone())
                }
            };
            let Some(prefix) = canonical
                .map(|canonical| format!("{canonical}+{name}"))
                .filter(|prefix| prefixes_in_use.contains(prefix.as_str()))
            else {
                eprintln!(
                    "[Warn] --labelOnlyModuleExtensions: {id} generates no repository the root module can see"
                );
                continue;
            };
            let disambiguated = prefixes_in_use.iter().any(|other| {
                other.strip_prefix(prefix.as_str()).is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                })
            });
            if disambiguated {
                eprintln!(
                    "[Warn] --labelOnlyModuleExtensions: {id} shares its name with another extension of its module, so its repositories cannot be told apart"
                );
                continue;
            }
            prefixes.insert(prefix);
        }
        prefixes
    }

    /// Canonical names that fit one invocation are asked for by name. More are asked of
    /// `--all_repos` in a single invocation, filtered to the names wanted: every invocation costs
    /// a Bazel server round trip (seconds on Windows, whose `cmd.exe` limit is the one that splits
    /// the names most finely, #536), and the names are nearly every repository anyway. A Bazel
    /// without `--all_repos`, or one whose answer a module extension it cannot evaluate
    /// spoils, is asked by name after all, one invocation per chunk.
    fn show_repositories_within<'a>(
        &self,
        canonical_names: &[String],
        failed: &mut FailedExtensions,
        budget: usize,
        hidden_bindings: impl FnOnce() -> Option<&'a BTreeMap<String, String>>,
    ) -> Result<Vec<Repository>> {
        // Hidden module keys start with a lowercase module name, after canonical @@ arguments.
        let canonical_count = canonical_names.partition_point(|name| name.starts_with("@@"));
        let (canonical, hidden) = canonical_names.split_at(canonical_count);
        let selected_bytes = canonical.iter().map(|name| name.len() + 1).sum::<usize>();
        if selected_bytes > budget {
            match self.show_all_repositories(failed) {
                Ok(Some(BulkRepositories {
                    mut by_canonical,
                    complete,
                })) => {
                    // A module-key request prints its canonical definition with one extra
                    // field. Reuse the bulk answer only when the parents' own repo mappings
                    // identify every key and the bulk command answered completely.
                    let hidden_records =
                        complete
                            .then(hidden_bindings)
                            .flatten()
                            .and_then(|bindings| {
                                hidden
                                    .iter()
                                    .map(|key| {
                                        let name = bindings.get(key)?;
                                        let record = by_canonical.get(name)?;
                                        if record.module_key.is_some()
                                            || record.apparent_name.is_some()
                                        {
                                            return None;
                                        }
                                        let mut record = record.clone();
                                        record.module_key = Some(key.clone());
                                        Some(record)
                                    })
                                    .collect::<Option<Vec<_>>>()
                            });
                    // RepoOverride has no streamed-proto record, so missing canonical slots
                    // remain omitted, in the same order as an explicit read.
                    let mut repositories: Vec<_> = canonical
                        .iter()
                        .filter_map(|name| by_canonical.remove(name.trim_start_matches('@')))
                        .collect();
                    repositories.extend(match hidden_records {
                        Some(records) => records,
                        None => self.show_repositories_explicit(hidden, failed, budget)?,
                    });
                    return Ok(repositories);
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!("[Warn] {error:#}; reading selected repositories explicitly");
                }
            }
            self.check_cancelled()?;
        }
        self.show_repositories_explicit(canonical_names, failed, budget)
    }

    fn show_repositories_explicit(
        &self,
        canonical_names: &[String],
        failed: &mut FailedExtensions,
        budget: usize,
    ) -> Result<Vec<Repository>> {
        let mut repositories = Vec::new();
        for chunk in chunk_arguments(canonical_names, budget) {
            let output_file = self.run_mod_over_repos("show_repo", chunk, failed, |names| {
                let output_file = NamedTempFile::new().context("create mod show_repo output")?;
                let mut command = self.command();
                command.arg("mod").arg("show_repo").args(names);
                command
                    .arg("--output=streamed_proto")
                    .stdout(File::create(output_file.path())?)
                    .stdin(Stdio::null())
                    .stderr(Stdio::piped());
                let output = self
                    .run_configured(&mut command)
                    .context("execute bazel mod show_repo")?;
                if output.status.success() && !output.stderr.is_empty() {
                    eprint!("{}", String::from_utf8_lossy(&output.stderr));
                }
                Ok((output.status, output.stderr, output_file))
            })?;
            if let Some(output_file) = output_file {
                repositories.extend(decode_delimited::<Repository>(output_file.path())?);
            }
        }
        Ok(repositories)
    }

    /// `bazel mod show_repo --all_repos --output=streamed_proto`. `None` when Bazel did not answer: it
    /// predates the option (every Bazel with the `--output=streamed_proto` this needs, 8.6
    /// and 9.0 on, has it), or a module extension it cannot evaluate failed the whole
    /// invocation. Failures are noted for the explicit reads that follow to identify
    /// unavailable canonical repositories.
    fn show_all_repositories(
        &self,
        failed: &mut FailedExtensions,
    ) -> Result<Option<BulkRepositories>> {
        let output_file = NamedTempFile::new().context("create mod show_repo output")?;
        let mut command = self.command();
        command
            .arg("mod")
            .arg("show_repo")
            .arg("--all_repos")
            .arg("--output=streamed_proto")
            .stdout(File::create(output_file.path())?)
            .stdin(Stdio::null())
            .stderr(Stdio::piped());
        if self.verbose {
            eprintln!("[Info] Command: {command:?}");
        }
        let output = self
            .run_configured(&mut command)
            .context("execute bazel mod show_repo --all_repos")?;
        let answered = if output.status.success() {
            true
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            match extension_failure(&stderr) {
                Some(failure) => {
                    self.note_failed_extensions(failed, failure.extensions);
                    failure.answered
                }
                None => {
                    if self.verbose {
                        eprintln!(
                            "[Info] bazel mod show_repo --all_repos failed with {}, asking by name instead: {}",
                            output.status,
                            stderr.trim()
                        );
                    }
                    false
                }
            }
        };
        if !answered {
            return Ok(None);
        }
        if !output.stderr.is_empty() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
        let mut complete = output.status.success() && failed.is_empty();
        let mut by_canonical = HashMap::new();
        for repository in decode_delimited::<Repository>(output_file.path())? {
            let Some(canonical) = repository.canonical_name.as_deref() else {
                complete = false;
                continue;
            };
            let canonical = canonical.trim_start_matches('@');
            if !has_unavailable_mapping(canonical, failed)
                && by_canonical
                    .insert(canonical.to_owned(), repository)
                    .is_some()
            {
                complete = false;
            }
        }
        Ok(Some(BulkRepositories {
            by_canonical,
            complete,
        }))
    }

    /// Enumerates every repository generated by a module extension that at least one module
    /// imports from. Module mappings name the extension repos they `use_repo`. A repository
    /// of each such extension sees its siblings, whether or not any module imports them.
    ///
    /// Mapping failures identify the unavailable canonical repositories before excluding them.
    fn extension_repositories(
        &self,
        canonical_to_apparent: &BTreeMap<String, Vec<String>>,
        hidden_module_repos: Vec<String>,
        prefetched: BTreeMap<String, RepoMapping>,
        complete_inputs: bool,
        failed: &mut FailedExtensions,
    ) -> Result<ExtensionRepositories> {
        let visible_module_repos = canonical_to_apparent
            .keys()
            .filter(|canonical| !is_extension_repo(canonical))
            .cloned()
            .collect::<Vec<_>>();
        let mut imported = canonical_to_apparent
            .keys()
            .filter(|canonical| is_extension_repo(canonical))
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut module_repos = visible_module_repos.clone();
        module_repos.extend(hidden_module_repos.iter().cloned());
        let mut module_mappings = BTreeMap::new();
        let mut complete_mappings = complete_inputs && failed.is_empty();
        if !module_repos.is_empty() {
            // The hidden modules' repository names are derived, not reported, so a derivation
            // Bazel disagrees with falls back to the root-visible modules alone.
            let mappings = match self.module_mappings(
                &module_repos,
                prefetched,
                failed,
                &mut complete_mappings,
            ) {
                Ok(mappings) => mappings,
                Err(error) if !hidden_module_repos.is_empty() => {
                    eprintln!("[Warn] {error:#}; enumerating extension repositories from the root-visible modules only");
                    complete_mappings = false;
                    self.dump_repo_mappings(&visible_module_repos, failed, &mut complete_mappings)?
                }
                Err(error) => return Err(error),
            };
            imported.extend(
                mappings
                    .iter()
                    .flat_map(|mapping| mapping.values())
                    .filter(|canonical| is_extension_repo(canonical))
                    .cloned(),
            );
            complete_mappings &= mappings.len() == module_repos.len();
            if complete_mappings && !hidden_module_repos.is_empty() {
                module_mappings.extend(module_repos.iter().cloned().zip(mappings));
            }
        }
        imported.retain(|canonical| !has_unavailable_mapping(canonical, failed));
        let mut representatives = BTreeMap::new();
        for canonical in &imported {
            if let Some((prefix, _)) = canonical.rsplit_once('+') {
                representatives
                    .entry(prefix.to_owned())
                    .or_insert_with(|| canonical.clone());
            }
        }
        let mut generated = imported.clone();
        let mut complete_spoke_mappings = true;
        if !representatives.is_empty() {
            let names = representatives.values().cloned().collect::<Vec<_>>();
            let mappings =
                match self.dump_repo_mappings(&names, failed, &mut complete_spoke_mappings) {
                    Ok(mappings) => mappings,
                    Err(_) => {
                        complete_spoke_mappings = false;
                        // One extension that fails to evaluate should not hide the rest; retry
                        // one at a time and report the ones Bazel cannot describe.
                        let mut mappings = Vec::new();
                        for name in &names {
                            match self.dump_repo_mappings(
                                std::slice::from_ref(name),
                                failed,
                                &mut complete_mappings,
                            ) {
                                Ok(mapping) => mappings.extend(mapping),
                                Err(error) if self.keep_going => {
                                    eprintln!(
                                    "[Warn] skipping the module extension behind {name}: {error:#}"
                                );
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        mappings
                    }
                };
            generated.extend(
                mappings
                    .into_iter()
                    .flat_map(|mapping| mapping.into_values())
                    .filter(|canonical| {
                        canonical
                            .rsplit_once('+')
                            .is_some_and(|(prefix, _)| representatives.contains_key(prefix))
                    }),
            );
        }
        imported.retain(|canonical| !has_unavailable_mapping(canonical, failed));
        generated.retain(|canonical| !has_unavailable_mapping(canonical, failed));
        if !complete_mappings || !complete_spoke_mappings {
            module_mappings.clear();
        }
        Ok(ExtensionRepositories {
            imported,
            generated,
            complete_mappings: complete_mappings && complete_spoke_mappings,
            module_mappings,
        })
    }

    fn module_mappings(
        &self,
        repos: &[String],
        mut prefetched: BTreeMap<String, RepoMapping>,
        failed: &mut FailedExtensions,
        complete: &mut bool,
    ) -> Result<Vec<RepoMapping>> {
        if prefetched.is_empty() {
            return self.dump_repo_mappings(repos, failed, complete);
        }
        let mut missing = Vec::new();
        let mut mappings = Vec::with_capacity(repos.len());
        for repo in repos {
            let mapping = prefetched.remove(repo);
            if mapping.is_none() {
                missing.push(repo.clone());
            }
            mappings.push(mapping);
        }
        let mut complete_missing = true;
        let answers = self.dump_repo_mappings(&missing, failed, &mut complete_missing)?;
        if !complete_missing {
            return self.dump_repo_mappings(repos, failed, complete);
        }
        let mut answers = answers.into_iter();
        Ok(mappings
            .into_iter()
            .map(|mapping| {
                mapping.unwrap_or_else(|| answers.next().expect("one answer per missing module"))
            })
            .collect())
    }

    /// `bazel mod dump_repo_mapping` over `repos` (canonical names without `@@`), one
    /// apparent -> canonical map per repository.
    fn dump_repo_mappings(
        &self,
        repos: &[String],
        failed: &mut FailedExtensions,
        complete: &mut bool,
    ) -> Result<Vec<RepoMapping>> {
        let mut mappings = Vec::new();
        for chunk in chunk_arguments(repos, mod_argument_byte_budget()) {
            let stdout = self.run_mod_over_repos("dump_repo_mapping", chunk, failed, |names| {
                let mut args = vec!["mod", "dump_repo_mapping"];
                args.extend(names.iter().map(String::as_str));
                let output = self.run_capture(&args)?;
                // Bazel prints mappings in argument order, without repository names. Keep
                // them bound to the requested names only if every original name was answered.
                *complete &= output.status.success() && names == chunk;
                Ok((output.status, output.stderr, output.stdout))
            })?;
            let Some(stdout) = stdout else {
                *complete = false;
                continue;
            };
            let start = mappings.len();
            for line in String::from_utf8_lossy(&stdout).lines() {
                match serde_json::from_str(line.trim()) {
                    Ok(mapping) => mappings.push(mapping),
                    Err(_) => *complete = false,
                }
            }
            *complete &= mappings.len() - start == chunk.len();
        }
        Ok(mappings)
    }

    /// Runs a `bazel mod` subcommand over `repos`, leaving out the repositories of module
    /// extensions Bazel cannot evaluate. Bazel answers for every other repository when such
    /// an extension merely sits in the dependency graph, but asking for one of its
    /// repositories by name fails the whole invocation with nothing printed, so the
    /// invocation is retried without them. `None` once no repository is left to ask about.
    fn run_mod_over_repos<T>(
        &self,
        subcommand: &str,
        repos: &[String],
        failed: &mut FailedExtensions,
        mut attempt: impl FnMut(&[String]) -> Result<(ExitStatus, Vec<u8>, T)>,
    ) -> Result<Option<T>> {
        let without_failed = |repos: &[String], failed: &FailedExtensions| {
            repos
                .iter()
                .filter(|repo| !has_unavailable_mapping(repo, failed))
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut repos = without_failed(repos, failed);
        loop {
            if repos.is_empty() {
                return Ok(None);
            }
            let (status, stderr, value) = attempt(&repos)?;
            if status.success() {
                return Ok(Some(value));
            }
            let stderr = String::from_utf8_lossy(&stderr);
            let Some(failure) = extension_failure(&stderr) else {
                bail!(
                    "bazel mod {subcommand} failed with {status}: {}",
                    stderr.trim()
                );
            };
            self.note_failed_extensions(failed, failure.extensions);
            if failure.answered {
                return Ok(Some(value));
            }
            self.find_unavailable_repositories(&repos, failed)?;
            let remaining = without_failed(&repos, failed);
            if remaining.len() == repos.len() {
                bail!(
                    "bazel mod {subcommand} failed with {status}: {}",
                    stderr.trim()
                );
            }
            repos = remaining;
        }
    }

    /// Identifies unavailable canonical repositories by splitting failed mapping batches.
    /// Successful batches need no per-repository calls. Unlike extension ids in diagnostics,
    /// these names include Bazel's disambiguation of equal symbols from different files.
    /// A successful mapping does not prove the internal repository itself exists.
    fn find_unavailable_repositories(
        &self,
        repos: &[String],
        failed: &mut FailedExtensions,
    ) -> Result<()> {
        let repos = repos
            .iter()
            .map(|repo| repo.trim_start_matches('@'))
            .filter(|repo| is_extension_repo(repo) && !failed.unavailable.contains(*repo))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut pending = chunk_arguments(&repos, mod_argument_byte_budget());
        pending.reverse();
        while let Some(repos) = pending.pop() {
            let mut args = vec!["mod", "dump_repo_mapping"];
            args.extend(repos.iter().map(String::as_str));
            let output = self.run_capture(&args)?;
            if output.status.success() {
                continue;
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            // dump_repo_mapping returns before the inspector's partial-answer path.
            let failure = extension_failure(&stderr).filter(|failure| !failure.answered);
            let Some(failure) = failure else {
                bail!(
                    "bazel mod dump_repo_mapping failed with {}: {}",
                    output.status,
                    stderr.trim()
                );
            };
            if let [repo] = repos {
                self.note_failed_extensions(failed, failure.extensions);
                failed.unavailable.insert(repo.clone());
            } else {
                let (left, right) = repos.split_at(repos.len() / 2);
                pending.push(right);
                pending.push(left);
            }
        }
        Ok(())
    }

    /// The stdout of a `bazel mod` invocation that takes no repository names, kept when the
    /// invocation only failed because a module extension in the graph cannot be evaluated.
    fn accept_mod_output(
        &self,
        output: Output,
        subcommand: &str,
        failed: &mut FailedExtensions,
    ) -> Result<Vec<u8>> {
        if output.status.success() {
            return Ok(output.stdout);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        match extension_failure(&stderr) {
            Some(failure) if failure.answered => {
                self.note_failed_extensions(failed, failure.extensions);
                Ok(output.stdout)
            }
            _ => bail!(
                "bazel mod {subcommand} failed with {}: {}",
                output.status,
                stderr.trim()
            ),
        }
    }

    fn note_failed_extensions(&self, failed: &mut FailedExtensions, extensions: BTreeSet<String>) {
        failed.observed = true;
        for extension in extensions {
            if failed.extensions.insert(extension.clone()) {
                eprintln!(
                    "[Warn] Bazel reported that module extension {extension} cannot be evaluated"
                );
            }
        }
    }

    /// `bazel query //...:all-targets` lists repository inputs without loading their
    /// dependencies, so it does not report their failed mappings (#531). Checks those inputs
    /// after an extension failure. Returns an error, or warns under `--keep_going`.
    fn check_failed_extension_references(
        &self,
        targets: &[Target],
        failed: &mut FailedExtensions,
        canonical_to_apparent: &BTreeMap<String, Vec<String>>,
    ) -> Result<()> {
        if failed.is_empty() {
            return Ok(());
        }
        let apparent_to_canonical = canonical_to_apparent
            .iter()
            .flat_map(|(canonical, apparent)| {
                apparent
                    .iter()
                    .map(move |name| (name.as_str(), canonical.as_str()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut referenced = BTreeSet::new();
        for target in targets {
            let mut labels = vec![target_name(target).unwrap_or_default()];
            if let Some(rule) = target.rule.as_option() {
                labels.extend(rule.rule_input.iter().map(String::as_str));
                labels.extend(
                    rule.configured_rule_input
                        .iter()
                        .filter_map(|input| input.label.as_deref()),
                );
            }
            for label in labels {
                let Some((repo, _)) = label.split_once("//") else {
                    continue;
                };
                let canonical = repo.strip_prefix("@@").or_else(|| {
                    let apparent = repo.strip_prefix('@')?;
                    apparent_to_canonical.get(apparent).copied()
                });
                if let Some(canonical) = canonical {
                    referenced.insert(canonical);
                }
            }
        }
        self.find_unavailable_repositories(
            &referenced
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            failed,
        )?;
        let unavailable_apparent = apparent_to_canonical
            .into_iter()
            .filter_map(|(apparent, canonical)| {
                has_unavailable_mapping(canonical, failed).then_some(apparent)
            })
            .collect::<BTreeSet<_>>();
        let unavailable = |label: &str| -> bool {
            let Some((repo, _)) = label.split_once("//") else {
                return false;
            };
            match repo.strip_prefix("@@") {
                Some(canonical) => has_unavailable_mapping(canonical, failed),
                None => repo
                    .strip_prefix('@')
                    .is_some_and(|apparent| unavailable_apparent.contains(apparent)),
            }
        };
        let mut offenders = Vec::new();
        for target in targets {
            let name = target_name(target).unwrap_or_default();
            let mut labels = vec![name];
            if let Some(rule) = target.rule.as_option() {
                labels.extend(rule.rule_input.iter().map(String::as_str));
                labels.extend(
                    rule.configured_rule_input
                        .iter()
                        .filter_map(|input| input.label.as_deref()),
                );
            }
            if let Some(label) = labels.into_iter().find(|label| unavailable(label)) {
                offenders.push(format!(
                    "{name} depends on {label}, whose repository mapping failed"
                ));
            }
        }
        if offenders.is_empty() {
            return Ok(());
        }
        let shown = offenders
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
        let more = offenders.len().saturating_sub(5);
        let summary = if more > 0 {
            format!("{shown}; and {more} more")
        } else {
            shown
        };
        if self.keep_going {
            eprintln!(
                "[Warn] hashes do not cover inputs with failed repository mappings: {summary}"
            );
            Ok(())
        } else {
            let reported = failed
                .extensions
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "repository mappings needed by targets failed: {summary}; reported module extensions: {reported}"
            )
        }
    }

    pub fn query(&self, expression: &str, use_cquery: bool) -> Result<Vec<Target>> {
        let mut targets = self.query_with(expression, use_cquery, None, &mut |_| {})?;
        if !use_cquery {
            // A standalone query returns exactly its requested records. Use the
            // same metadata boundary as hash_targets when its caller requested
            // typed output, including through an effective bazelrc setting.
            let typed = self.static_toolchain_scope_matches()
                && (self.uses_declared_types()
                    || targets.iter().any(|target| {
                        target
                            .rule
                            .as_option()
                            .is_some_and(|rule| rule.possible_toolchain_types.as_option().is_some())
                    }));
            let direct = typed
                && self.module_graph_output()?.1.is_some()
                && self
                    .with_possible_toolchain_types(true)?
                    .uses_declared_types();
            if !direct {
                targets.iter_mut().for_each(add_legacy_toolchain_inputs);
            }
        }
        Ok(targets)
    }

    fn query_with(
        &self,
        expression: &str,
        use_cquery: bool,
        version: Option<BazelVersion>,
        transform: &mut impl FnMut(&mut [Target]),
    ) -> Result<Vec<Target>> {
        self.query_with_filtered(expression, use_cquery, version, transform, |_| true)
    }

    /// With nodep edges disabled, a walk limited to one step adds RuleClass
    /// toolchain defaults to ordinary attribute inputs. A complete proto witness with conservative
    /// aspects includes the other walked inputs, so their difference belongs to
    /// the class. A peer separates a default masked by an ordinary occurrence.
    fn add_unreported_query_inputs(
        &self,
        targets: &mut [Target],
        mapping: &HashMap<String, String>,
        classes: &BTreeMap<String, StockRuleClass>,
        reads: &mut SupplierReads,
        version: BazelVersion,
    ) -> Result<()> {
        let groups = classes.values().collect::<Vec<_>>();
        let mut samples = BTreeMap::<String, Vec<usize>>::new();
        for StockRuleClass {
            representative,
            members,
        } in &groups
        {
            let name = target_name(&targets[*representative]).expect("indexed rule");
            let owner = canonical_query_label(name, mapping);
            samples
                .entry(owner.as_ref().to_owned())
                .or_default()
                .extend(members.iter().copied().filter(|&index| {
                    target_name(&targets[index])
                        .is_some_and(|name| canonical_query_label(name, mapping) == owner)
                }));
        }
        let first = self.walked_query_inputs(samples.keys(), mapping, version)?;
        let first_flat = self.flat_query_inputs(samples.keys(), mapping, version)?;
        let mut local = BTreeMap::<usize, BTreeSet<String>>::new();
        queue_stock_inputs(&first, &samples, targets, mapping, &mut local);
        let mut additions = BTreeMap::<usize, BTreeSet<String>>::new();
        let mut uncertain = BTreeMap::<usize, BTreeSet<String>>::new();
        let mut peers = BTreeMap::<String, Vec<usize>>::new();
        let mut peer_groups = BTreeMap::<String, BTreeSet<usize>>::new();
        let mut overlaps = Vec::<(usize, String, String)>::new();
        for (
            group,
            StockRuleClass {
                representative,
                members,
            },
        ) in groups.iter().enumerate()
        {
            let rule = targets[*representative]
                .rule
                .as_option()
                .expect("indexed rule");
            let owner = canonical_query_label(&rule.name, mapping);
            let Some(inputs) = first.inputs.get(owner.as_ref()) else {
                continue;
            };
            let Some(ordinary) = first_flat.inputs(owner.as_ref()) else {
                for input in inputs {
                    queue_stock_uncertainty(&mut uncertain, group, input);
                }
                continue;
            };
            additions.entry(group).or_default().extend(
                inputs
                    .iter()
                    .filter(|input| !ordinary.contains(*input))
                    .cloned(),
            );
            let mut masked = inputs
                .iter()
                .filter(|input| ordinary.contains(*input))
                .cloned()
                .collect::<BTreeSet<_>>();
            let mut unquotable = BTreeSet::new();
            let mut ordered = members.to_vec();
            ordered.sort_unstable_by(|left, right| {
                target_name(&targets[*left])
                    .expect("indexed rule")
                    .cmp(target_name(&targets[*right]).expect("indexed rule"))
                    .then_with(|| left.cmp(right))
            });
            for index in ordered {
                if masked.is_empty() {
                    break;
                }
                let rule = targets[index].rule.as_option().expect("indexed rule");
                let name = canonical_query_label(&rule.name, mapping);
                if name == owner {
                    continue;
                }
                let present = rule
                    .rule_input
                    .iter()
                    .map(|input| canonical_query_label(input, mapping))
                    .filter(|input| masked.contains(input.as_ref()))
                    .map(Cow::into_owned)
                    .collect::<HashSet<_>>();
                if present.len() == masked.len() {
                    continue;
                }
                let missing = masked
                    .iter()
                    .filter(|input| !present.contains(*input))
                    .cloned()
                    .collect::<Vec<_>>();
                if name.contains('"') {
                    unquotable.extend(missing);
                    continue;
                }
                let name = name.into_owned();
                peers.entry(name.clone()).or_default().push(index);
                peer_groups.entry(name.clone()).or_default().insert(group);
                for input in missing {
                    masked.remove(&input);
                    overlaps.push((group, input, name.clone()));
                }
            }
            for input in masked.intersection(&unquotable) {
                queue_stock_uncertainty(&mut uncertain, group, input);
            }
        }
        let second = self.walked_query_inputs(peers.keys(), mapping, version)?;
        let second_flat = self.flat_query_inputs(peers.keys(), mapping, version)?;
        queue_stock_inputs(&second, &peers, targets, mapping, &mut local);
        for (owner, inputs) in &second.inputs {
            let Some(samples) = peer_groups.get(owner) else {
                continue;
            };
            for &group in samples {
                if let Some(ordinary) = second_flat.inputs(owner) {
                    additions.entry(group).or_default().extend(
                        inputs
                            .iter()
                            .filter(|input| !ordinary.contains(*input))
                            .cloned(),
                    );
                } else {
                    for input in inputs {
                        queue_stock_uncertainty(&mut uncertain, group, input);
                    }
                }
            }
        }
        for (group, input, peer) in overlaps {
            let answered = second_flat
                .inputs(&peer)
                .filter(|ordinary| !ordinary.contains(&input))
                .and_then(|_| second.has_input(&peer, &input));
            if answered.is_none() {
                queue_stock_uncertainty(&mut uncertain, group, &input);
            }
        }
        let mut observed = HashMap::<String, usize>::new();
        let wanted = local
            .values()
            .chain(additions.values())
            .flatten()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        for (index, target) in targets.iter().enumerate() {
            let Some(name) = target_name(target).filter(|name| !name.starts_with("//external:"))
            else {
                continue;
            };
            let canonical = canonical_query_label(name, mapping);
            if !wanted.contains(canonical.as_ref()) {
                continue;
            }
            observed
                .entry(canonical.into_owned())
                .and_modify(|previous| {
                    if name < target_name(&targets[*previous]).expect("indexed target") {
                        *previous = index;
                    }
                })
                .or_insert(index);
        }
        for (index, inputs) in local {
            add_stock_inputs(targets, &[index], &inputs, mapping, &observed);
        }
        for (group, inputs) in additions {
            add_stock_inputs(targets, &groups[group].members, &inputs, mapping, &observed);
        }
        for (group, repositories) in uncertain {
            for &index in &groups[group].members {
                let name = target_name(&targets[index]).expect("indexed rule");
                reads
                    .uncertain_class_repositories
                    .entry(name.to_owned())
                    .or_default()
                    .extend(repositories.iter().cloned());
            }
        }
        Ok(())
    }

    /// A loading walk limited to one step. Partial output supplies positive edges only.
    fn walked_query_inputs<'a>(
        &self,
        roots: impl IntoIterator<Item = &'a String>,
        mapping: &HashMap<String, String>,
        version: BazelVersion,
    ) -> Result<StockWalk> {
        let roots = roots.into_iter().cloned().collect::<BTreeSet<_>>();
        if roots.is_empty() {
            return Ok(StockWalk::default());
        }
        let expression = format!("deps({}, 1)", query_set(&roots)?);
        let (output_file, output) = self
            .query_output(&expression, version, QueryFormat::Walked)
            .context("failed to read walked query inputs")?;
        self.check_cancelled()?;
        if !matches!(output.status.code(), Some(0 | 3 | 7)) {
            return Err(QueryFailure {
                code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
            .into());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut answer = StockWalk {
            inputs: BTreeMap::new(),
            returned: BTreeSet::new(),
            unrecognized: BTreeSet::new(),
            complete: output.status.success() && !stderr.contains("ERROR:"),
        };
        if !answer.complete {
            eprintln!("[Warn] Walked query inputs are incomplete; retaining only returned edges");
        }
        if self.verbose && !stderr.is_empty() {
            eprint!("{stderr}");
        }
        for line in BufReader::new(File::open(output_file.path())?).lines() {
            let line = line?;
            let Some(body) = line
                .strip_prefix("  \"")
                .and_then(|body| body.strip_suffix('"'))
            else {
                continue;
            };
            if let Some((owner, input)) = body.split_once("\" -> \"") {
                if owner.contains('"') {
                    continue;
                }
                let owner = canonical_query_label(owner, mapping).into_owned();
                if !roots.contains(&owner) {
                    continue;
                }
                answer.returned.insert(owner.clone());
                // Bazel writes raw labels in DOT; an embedded quote is ambiguous.
                if input.contains('"') {
                    answer.unrecognized.insert(owner);
                    continue;
                }
                answer
                    .inputs
                    .entry(owner)
                    .or_default()
                    .insert(canonical_query_label(input, mapping).into_owned());
            } else if !body.contains('"') {
                let name = canonical_query_label(body, mapping).into_owned();
                if roots.contains(&name) {
                    answer.returned.insert(name);
                }
            }
        }
        Ok(answer)
    }

    /// A complete flat witness contains ordinary and conservative aspect inputs.
    /// Its projection is private to comparison and does not replace the primary row.
    fn flat_query_inputs<'a>(
        &self,
        roots: impl IntoIterator<Item = &'a String>,
        mapping: &HashMap<String, String>,
        version: BazelVersion,
    ) -> Result<StockFlat> {
        let roots = roots.into_iter().cloned().collect::<BTreeSet<_>>();
        if roots.is_empty() {
            return Ok(StockFlat::default());
        }
        let mut probe = self.clone();
        probe.keep_going = false;
        probe.command_options.extend([
            "--nonodep_deps".into(),
            "--aspect_deps=conservative".into(),
            "--proto:rule_inputs_and_outputs".into(),
            "--proto:output_rule_attrs=tags".into(),
            "--consistent_labels".into(),
            "--nofetch".into(),
            "--nokeep_going".into(),
        ]);
        let (rows, complete) = match probe.query_with_filtered_status(
            &query_set(&roots)?,
            false,
            Some(version),
            &mut |_| {},
            |_| true,
            false,
        ) {
            Ok(answer) => answer,
            Err(error) => {
                self.check_cancelled()?;
                if error
                    .downcast_ref::<QueryFailure>()
                    .is_some_and(|failure| matches!(failure.code, Some(3 | 7)))
                {
                    return Ok(StockFlat::default());
                }
                return Err(error);
            }
        };
        let mut inputs = BTreeMap::new();
        let mut duplicates = BTreeSet::new();
        for row in rows {
            let Some(rule) = row.rule.into_option() else {
                continue;
            };
            let name = canonical_query_label(&rule.name, mapping).into_owned();
            if !roots.contains(&name) {
                continue;
            }
            let ordinary = rule
                .rule_input
                .iter()
                .map(|input| canonical_query_label(input, mapping).into_owned())
                .collect();
            if inputs.insert(name.clone(), ordinary).is_some() {
                duplicates.insert(name);
            }
        }
        inputs.retain(|name, _| !duplicates.contains(name));
        Ok(StockFlat { inputs, complete })
    }

    fn query_with_filtered(
        &self,
        expression: &str,
        use_cquery: bool,
        version: Option<BazelVersion>,
        transform: &mut impl FnMut(&mut [Target]),
        retain: impl FnMut(&Target) -> bool,
    ) -> Result<Vec<Target>> {
        self.query_with_filtered_status(expression, use_cquery, version, transform, retain, false)
            .map(|(rows, _)| rows)
    }

    /// Run one query format with shared output files and cancellation handling.
    fn query_output(
        &self,
        expression: &str,
        version: BazelVersion,
        format: QueryFormat,
    ) -> Result<(NamedTempFile, Output)> {
        let query_file = NamedTempFile::new().context("create query file")?;
        fs::write(query_file.path(), expression).context("write query file")?;
        let output_file = NamedTempFile::new().context("create query output file")?;
        let mut command = self.command();
        let supports_output_file = match format {
            QueryFormat::Ordinary { keep_class_keys } => {
                command
                    .arg("query")
                    .arg("--output")
                    .arg("streamed_proto")
                    .arg("--proto:instantiation_stack")
                    .arg("--order_output=no");
                if keep_class_keys {
                    // Explicit caller options follow and can turn this projection off.
                    command.arg("--proto:rule_classes");
                }
                if self.keep_going {
                    command.arg("--keep_going");
                }
                command.args(&self.command_options);
                version >= BazelVersion(8, 2, 0)
            }
            QueryFormat::Configured => {
                command
                    .arg("cquery")
                    .arg("--transitions=lite")
                    .arg("--output")
                    .arg(if version >= BazelVersion(7, 0, 0) {
                        "streamed_proto"
                    } else {
                        "proto"
                    })
                    .arg("--proto:instantiation_stack");
                if self.keep_going {
                    command.arg("--keep_going");
                }
                command
                    .args(&self.cquery_options)
                    .arg("--consistent_labels");
                version >= BazelVersion(8, 2, 0)
            }
            QueryFormat::Walked => {
                command.arg("query").args(&self.command_options).args([
                    "--output=graph",
                    "--nograph:factored",
                    "--graph:conditional_edges_limit=0",
                    "--consistent_labels",
                    "--nonodep_deps",
                    "--nofetch",
                    "--keep_going",
                ]);
                false
            }
        };
        command.arg("--query_file").arg(query_file.path());
        if supports_output_file {
            command.arg("--output_file").arg(output_file.path());
            command.stdout(Stdio::null());
        } else {
            command.stdout(File::create(output_file.path())?);
        }
        command.stdin(Stdio::null()).stderr(Stdio::piped());
        if self.verbose {
            eprintln!("[Info] Executing Query: {expression}");
            eprintln!("[Info] Command: {command:?}");
        }
        let output = self
            .run_configured(&mut command)
            .context("failed to execute Bazel query")?;
        Ok((output_file, output))
    }

    fn query_with_filtered_status(
        &self,
        expression: &str,
        use_cquery: bool,
        version: Option<BazelVersion>,
        transform: &mut impl FnMut(&mut [Target]),
        retain: impl FnMut(&Target) -> bool,
        keep_class_keys: bool,
    ) -> Result<(Vec<Target>, bool)> {
        let version = match version {
            Some(version) => version,
            None => self.version()?,
        };
        let compatible = if use_cquery {
            Some(self.query_compatible_labels(expression)?)
        } else {
            None
        };
        let streamed_cquery = version >= BazelVersion(7, 0, 0);
        let format = if use_cquery {
            QueryFormat::Configured
        } else {
            QueryFormat::Ordinary { keep_class_keys }
        };
        let (output_file, output) = self.query_output(expression, version, format)?;
        let code = output.status.code().unwrap_or(-1);
        if code != 0 && !(self.keep_going && code == 3) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(QueryFailure {
                code: output.status.code(),
                stderr: stderr.into_owned(),
            }
            .into());
        }
        if !output.stderr.is_empty() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }

        let mut targets = if use_cquery {
            decode_cquery_stream(output_file.path(), streamed_cquery, transform)?
        } else {
            decode_target_stream_filtered(output_file.path(), transform, retain, keep_class_keys)?
        };
        if let Some(compatible) = compatible {
            targets.retain(|target| {
                target_name(target).is_some_and(|name| {
                    compatible.contains(main_repo_label_key(target_label(name)))
                })
            });
        }
        let complete = code == 0 && !String::from_utf8_lossy(&output.stderr).contains("ERROR:");
        Ok((targets, complete))
    }

    fn query_compatible_labels(&self, expression: &str) -> Result<HashSet<String>> {
        let query_file = NamedTempFile::new().context("create query file")?;
        fs::write(query_file.path(), expression)?;
        let starlark_file = NamedTempFile::new().context("create cquery formatter")?;
        fs::write(
            starlark_file.path(),
            r#"def format(target):
    if providers(target) == None:
        return ""
    if "IncompatiblePlatformProvider" not in providers(target):
        target_repr = repr(target)
        if "<alias target" in target_repr:
            # repr() prints a main-repository alias with its apparent label
            # (`//:tool`) even under --consistent_labels, while every other
            # target comes back as `@@//:tool` under Bzlmod and `@//:tool` in
            # WORKSPACE mode. The labels are compared through
            # main_repo_label_key, which puts all three in one form.
            return target_repr.split(" ")[2]
        return str(target.label)
    return ""
"#,
        )?;
        let mut command = self.command();
        command
            .arg("cquery")
            .arg("--output")
            .arg("starlark")
            .arg("--starlark:file")
            .arg(starlark_file.path())
            .args(&self.cquery_options)
            .arg("--consistent_labels")
            .arg("--query_file")
            .arg(query_file.path())
            .stdin(Stdio::null());
        let output = self
            .run(&mut command)
            .context("execute compatible-target cquery")?;
        if !output.status.success() {
            bail!(
                "compatible-target cquery failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| main_repo_label_key(line).to_owned())
            .collect())
    }

    fn canonical_bzlmod_repo_names(&self) -> Result<Vec<String>> {
        let mapping_output = self.run_capture(&["mod", "dump_repo_mapping", ""])?;
        let mapping = self.accept_mod_output(
            mapping_output,
            "dump_repo_mapping",
            &mut FailedExtensions::default(),
        )?;
        Ok(parse_repo_mapping(&String::from_utf8_lossy(&mapping))
            .keys()
            .filter(|name| name.contains('+') || name.contains('~'))
            .map(|name| format!("@@{name}"))
            .collect::<Vec<_>>())
    }

    fn show_repo_streamed_proto(&self, canonical_names: &[String]) -> Result<Vec<u8>> {
        if canonical_names.is_empty() {
            return Ok(Vec::new());
        }
        let output = self.run_mod_over_repos(
            "show_repo",
            canonical_names,
            &mut FailedExtensions::default(),
            |names| {
                let mut command = self.command();
                command
                    .arg("mod")
                    .arg("show_repo")
                    .args(names)
                    .arg("--output=streamed_proto")
                    .stdin(Stdio::null())
                    .stderr(Stdio::piped());
                eprintln!(
                    "[BD-DBG][fingerprint-command] path=streamed_proto_selected cmd={command:?}"
                );
                if self.verbose {
                    eprintln!("[Info] Command: {command:?}");
                }
                let output = self
                    .run(&mut command)
                    .context("execute bazel mod show_repo streamed_proto")?;
                Ok((output.status, output.stderr, output.stdout))
            },
        )?;
        Ok(output.unwrap_or_default())
    }

    fn show_repo_fingerprint_text_fallback(&self, canonical_names: &[String]) -> Result<String> {
        let mut all_visible_command = self.command();
        all_visible_command
            .arg("mod")
            .arg("show_repo")
            .arg("--all_visible_repos")
            .arg("--output=text");
        eprintln!(
            "[BD-DBG][fingerprint-command] path=text_all_visible cmd={all_visible_command:?}"
        );
        all_visible_command
            .stdin(Stdio::null())
            .stderr(Stdio::piped());
        let output = self.run(&mut all_visible_command);
        if let Ok(output) = output {
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
            }
        }

        let mut command = self.command();
        command.arg("mod").arg("show_repo");
        if canonical_names.is_empty() {
            command.arg("--output=text");
        } else {
            command.args(canonical_names).arg("--output=text");
        }
        eprintln!("[BD-DBG][fingerprint-command] path=text_selected_repos cmd={command:?}");
        command.stdin(Stdio::null()).stderr(Stdio::piped());
        let output = self
            .run(&mut command)
            .context("execute bazel mod show_repo")?;
        if !output.stderr.is_empty() && self.verbose {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
        if !output.status.success() {
            bail!("bazel mod show_repo failed with {}", output.status);
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

fn parse_repo_mapping(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut canonical_to_apparent = BTreeMap::<String, Vec<String>>::new();
    for line in text.lines() {
        let value: serde_json::Value = match serde_json::from_str(line.trim()) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(mapping) = value.as_object() else {
            continue;
        };
        for (apparent, canonical) in mapping {
            let Some(canonical) = canonical.as_str() else {
                continue;
            };
            if apparent.is_empty()
                || canonical.is_empty()
                || canonical.starts_with("bazel_tools")
                || canonical.starts_with("_builtins")
                || canonical.starts_with("local_config_")
                || canonical.starts_with("rules_java_builtin")
            {
                continue;
            }
            canonical_to_apparent
                .entry(canonical.to_owned())
                .or_default()
                .push(apparent.clone());
        }
    }
    canonical_to_apparent
}

#[derive(Default)]
struct ModuleSurvey {
    graph: Option<Output>,
    toolchain_registrations: Option<ModuleToolchainRegistrations>,
    mappings: BTreeMap<String, RepoMapping>,
}

/// Canonical names of the repositories module extensions generate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ExtensionRepositories {
    /// The ones some module (the root included) imports with `use_repo`: the hubs, toolchain
    /// registries and rule repos that targets name.
    imported: BTreeSet<String>,
    /// Every repository of every extension in `imported`, the imported ones included.
    generated: BTreeSet<String>,
    /// All modules and extension representatives supplied their requested mapping.
    complete_mappings: bool,
    /// Complete module mappings from the ordinary module read, keyed by their requested canonical names.
    module_mappings: BTreeMap<String, RepoMapping>,
}

#[derive(Default)]
struct IsolatedRepoScope {
    anchor: String,
    members: BTreeSet<String>,
    aliases: RepoMapping,
    // Typed labels addressed by the usage's repository rules, including non-source targets.
    repository_inputs: BTreeSet<String>,
}

fn query_labels<'a>(labels: impl Iterator<Item = &'a String>) -> Result<String> {
    labels
        .map(|label| {
            if !label.contains('\'') {
                Ok(format!("'{label}'"))
            } else if !label.contains('"') {
                Ok(format!("\"{label}\""))
            } else {
                bail!("cannot quote Bazel query label {label}")
            }
        })
        .collect::<Result<Vec<_>>>()
        .map(|labels| labels.join(" + "))
}

/// Native rules that Bazel itself evaluates when matching a select condition.
pub(crate) fn is_condition_class(class: &str) -> bool {
    matches!(
        class,
        "config_setting" | "constraint_value" | "constraint_setting"
    )
}

pub(crate) fn canonical_query_label<'a>(
    label: &'a str,
    mapping: &HashMap<String, String>,
) -> Cow<'a, str> {
    let label = main_repo_label_key(label);
    if let Some((repo, target)) = label.strip_prefix('@').and_then(|s| s.split_once("//")) {
        if let Some(canonical) = mapping.get(repo) {
            return Cow::Owned(format!("@@{canonical}//{target}"));
        }
    }
    Cow::Borrowed(label)
}

fn target_inputs(target: &Target) -> impl Iterator<Item = &String> {
    target
        .rule
        .as_option()
        .into_iter()
        .flat_map(|r| r.rule_input.iter())
        .chain(
            target
                .generated_file
                .as_option()
                .map(|f| &f.generating_rule),
        )
}

fn query_set<'a>(labels: impl IntoIterator<Item = &'a String>) -> Result<String> {
    let operands = labels
        .into_iter()
        .map(|label| query_labels(std::iter::once(label)))
        .collect::<Result<Vec<_>>>()?;
    Ok(format!("set({})", operands.join(" ")))
}

/// Coverage of the retained primary targets followed by any accepted supplement.
#[derive(Default)]
struct ScopedCoverage {
    names: HashSet<String>,
    files: HashSet<String>,
    missing: BTreeSet<String>,
    direct_readers: Vec<bool>,
}

impl ScopedCoverage {
    fn record(&mut self, scope: &IsolatedRepoScope, targets: &[Target]) {
        for target in targets {
            if let Some(name) = target_name(target).and_then(|name| scope.canonical(name)) {
                self.missing.remove(&name);
                self.names.insert(name);
            }
            if let Some(name) = target
                .source_file
                .as_option()
                .and_then(|file| scope.canonical(&file.name))
            {
                self.files.insert(name);
            }
        }
        for target in targets {
            let mut direct = false;
            if let Some(rule) = target.rule.as_option() {
                for input in rule
                    .rule_input
                    .iter()
                    .filter_map(|label| scope.canonical(label))
                {
                    direct = true;
                    if !self.names.contains(&input) {
                        self.missing.insert(input);
                    }
                }
            }
            self.direct_readers.push(direct);
        }
    }
}

// The primary wins on equal names. Preserve repeated records in the supplement
// when no primary record has their name.
fn retain_supplemental_targets(extra: &mut Vec<Target>, primary: &[Target]) {
    if extra.is_empty() {
        return;
    }
    let primary_names = primary.iter().filter_map(target_name);
    let present: HashSet<_> = if extra.len() <= primary.len() / 2 {
        let names: HashSet<_> = extra.iter().filter_map(target_name).collect();
        primary_names.filter(|name| names.contains(name)).collect()
    } else {
        primary_names.collect()
    };
    extra.retain(|target| target_name(target).is_some_and(|name| !present.contains(name)));
}

impl IsolatedRepoScope {
    fn expression(&self, ordinary: &str) -> String {
        format!("let members = deps('@{}//...:all-targets') in ({ordinary}) + $members + buildfiles($members)", self.anchor)
    }

    fn canonical(&self, label: &str) -> Option<String> {
        let (repo, rest) = label.strip_prefix('@')?.split_once("//")?;
        let canonical = if let Some(name) = repo.strip_prefix('@') {
            self.members.get(name)?
        } else {
            self.members.get(self.aliases.get(repo)?)?
        };
        Some(format!("@@{canonical}//{rest}"))
    }

    fn package<'a>(&self, label: &'a str) -> Cow<'a, str> {
        let package = label.rsplit_once(':').map_or(label, |(package, _)| package);
        if let Some((repo, path)) = package
            .strip_prefix('@')
            .and_then(|label| label.split_once("//"))
        {
            if repo.starts_with('@') && repo.len() > 1 {
                return Cow::Borrowed(package);
            }
            let canonical = repo
                .strip_prefix('@')
                .or_else(|| self.aliases.get(repo).map(String::as_str));
            if let Some(repo) = canonical {
                return if repo.is_empty() {
                    Cow::Owned(format!("//{path}"))
                } else {
                    Cow::Owned(format!("@@{repo}//{path}"))
                };
            }
        }
        Cow::Borrowed(package)
    }

    // Ordinary query can emit two source records for a BUILD, even within one stream.
    // Keep the union of observed load edges before normal first-record deduplication.
    fn record_build_loads(
        &self,
        batch: &[Target],
        loads_by_package: &mut BTreeMap<String, BTreeSet<String>>,
    ) {
        for source in batch
            .iter()
            .filter_map(|target| target.source_file.as_option())
        {
            let Some((_, "BUILD" | "BUILD.bazel")) = source.name.rsplit_once(':') else {
                continue;
            };
            if self.canonical(&source.name).is_some() {
                loads_by_package
                    .entry(source.name.clone())
                    .or_default()
                    .extend(source.subinclude.iter().cloned());
            } else {
                for load in source
                    .subinclude
                    .iter()
                    .filter_map(|load| self.canonical(load))
                {
                    loads_by_package
                        .entry(source.name.clone())
                        .or_default()
                        .insert(load);
                }
            }
        }
    }

    fn connect_external_readers(
        &self,
        loads_by_package: &BTreeMap<String, BTreeSet<String>>,
        targets: &mut [Target],
        coverage: &ScopedCoverage,
    ) -> Result<()> {
        debug_assert_eq!(targets.len(), coverage.direct_readers.len());
        let mut readers = BTreeSet::new();
        for (build, loads) in loads_by_package {
            for load in loads.iter().filter_map(|label| self.canonical(label)) {
                if !coverage.files.contains(&load) {
                    bail!("--isolatedDependencyRoot: buildfiles did not return scoped load {load}");
                }
                readers.insert(self.package(build));
            }
        }
        let root = format!("//external:{}", self.anchor);
        for (index, target) in targets.iter_mut().enumerate() {
            if let Some(source) = target.source_file.as_option_mut() {
                if self.canonical(&source.name).is_some() {
                    if let Some(loads) = loads_by_package.get(&source.name) {
                        source.subinclude = loads.iter().cloned().collect();
                    }
                }
            }
            if let Some(rule) = target.rule.as_option_mut() {
                if !rule.name.starts_with("//external:")
                    && self.canonical(&rule.name).is_none()
                    && (coverage.direct_readers[index]
                        || (!readers.is_empty()
                            && readers.contains(self.package(&rule.name).as_ref())))
                    && !rule.rule_input.contains(&root)
                {
                    rule.rule_input.push(root.clone());
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct LabelOnlyRepositories {
    /// Usage prefixes of `label_only_module_extensions`; their owners get no stand-in edges.
    extensions: BTreeSet<String>,
    owner_exemptions: BTreeSet<String>,
}

/// Bind the effective root import to one returned extension usage. Its one imported
/// hub already depends on every hidden member; use that same aggregate at its readers.
fn resolve_isolated_root(
    root: &str,
    root_mapping: &[u8],
    survey: &ExtensionRepositories,
    repositories: &[Repository],
) -> Result<IsolatedRepoScope> {
    let name = root
        .strip_prefix('@')
        .context("expected an apparent repository name beginning with @")?;
    if name.is_empty() || name.contains(['@', '/', '%', '+', ':']) {
        bail!("expected one apparent repository name without a path or canonical prefix");
    }
    let mapping: RepoMapping =
        serde_json::from_slice(root_mapping).context("invalid root repository mapping")?;
    let hub = mapping
        .get(name)
        .context("root import is missing from the repository mapping")?;
    let group = effective_root_group(hub, survey, repositories)?;
    if let Some(other) = survey
        .imported
        .iter()
        .find(|other| *other != hub && extension_usage_prefix(other) == Some(group))
    {
        bail!("extra imported repository {other} belongs to the isolated usage");
    }
    let members: BTreeSet<_> = survey
        .generated
        .iter()
        .filter(|repo| extension_usage_prefix(repo) == Some(group))
        .cloned()
        .collect();
    let mut inputs = BTreeSet::new();
    for repo in repositories {
        let display_name = repo
            .canonical_name
            .as_deref()
            .or(repo.original_name.as_deref())
            .unwrap_or("<unnamed>");
        for attr in &repo.attribute {
            use crate::proto::blaze_query::attribute::Discriminator as Kind;
            if !attr.__buffa_unknown_fields.is_empty() {
                bail!(
                    "repository {display_name} attribute {} has unknown protobuf fields",
                    attr.name
                );
            }
            if matches!(
                attr.r#type,
                Kind::Unknown
                    | Kind::SelectorList
                    | Kind::FilesetEntryList
                    | Kind::License
                    | Kind::Output
                    | Kind::OutputList
            ) {
                bail!(
                    "repository {display_name} attribute {} has unsupported type {:?}",
                    attr.name,
                    attr.r#type
                );
            }
            if !matches!(
                attr.r#type,
                Kind::Label
                    | Kind::LabelList
                    | Kind::LabelListDict
                    | Kind::LabelDictUnary
                    | Kind::LabelKeyedStringDict
            ) {
                continue;
            }
            for value in attribute_label_values(attr) {
                let reader = repo.canonical_name.as_deref().with_context(|| {
                    format!(
                        "repository {display_name} attribute {} has no canonical repository name",
                        attr.name
                    )
                })?;
                let canonical = if value.starts_with("@@") {
                    value.to_owned()
                } else if value.starts_with("//") {
                    format!("@@{value}")
                } else if value.starts_with('@') {
                    bail!(
                        "repository {reader} attribute {} has unresolved label {value}",
                        attr.name
                    );
                } else {
                    continue;
                };
                let (target, _) = canonical[2..].split_once("//").with_context(|| {
                    format!(
                        "repository {reader} attribute {} has invalid label {canonical}",
                        attr.name
                    )
                })?;
                if members.contains(reader) {
                    inputs.insert(canonical);
                } else if members.contains(target) {
                    // A repository generator outside the usage may consume a file
                    // without producing any ordinary target edge.
                    bail!(
                        "outside repository {reader} attribute {} reads {canonical}",
                        attr.name
                    );
                }
            }
        }
    }
    Ok(IsolatedRepoScope {
        anchor: name.to_owned(),
        aliases: mapping,
        members,
        repository_inputs: inputs,
    })
}

/// Bazel assigns each root-isolated usage its own canonical prefix. Its module and
/// version slots are both empty, followed by the exported usage name. Repository names
/// themselves cannot contain '+'. Verify that every returned original name agrees with
/// that prefix, and that no other root import identifies a different group of that name.
fn effective_root_group<'a>(
    hub: &'a str,
    survey: &ExtensionRepositories,
    repositories: &[Repository],
) -> Result<&'a str> {
    fn root_export(prefix: &str) -> Option<&str> {
        let (owner_and_symbol, name) = prefix.rsplit_once("+++")?;
        let (_owner, symbol) = owner_and_symbol.rsplit_once("+_")?;
        (!symbol.is_empty() && !symbol.contains('+') && !name.is_empty() && !name.contains('+'))
            .then_some(name)
    }
    let group = extension_usage_prefix(hub)
        .with_context(|| format!("mapped repository {hub} is not an extension repository"))?;
    let usage = root_export(group).with_context(|| {
        format!("mapped repository {hub} is not a root-isolated extension usage")
    })?;
    if !survey.imported.contains(hub) {
        bail!("mapped repository {hub} is not imported");
    }
    for imported in &survey.imported {
        let Some(candidate) = extension_usage_prefix(imported) else {
            continue;
        };
        if candidate != group && root_export(candidate) == Some(usage) {
            bail!("root-isolated usage name {usage} conflicts with imported repository {imported}");
        }
    }
    let mut seen = BTreeSet::new();
    for row in repositories {
        let Some(name) = row.canonical_name.as_deref() else {
            continue;
        };
        let Some((prefix, original)) = name.rsplit_once('+') else {
            continue;
        };
        if prefix != group {
            continue;
        }
        if original.is_empty() {
            bail!("repository {name} has an empty original name");
        }
        if row.original_name.as_deref() != Some(original) {
            bail!(
                "repository {name} reported original name {:?}, expected {original}",
                row.original_name
            );
        }
        if !seen.insert(name) {
            bail!("repository {name} appears more than once in the catalog");
        }
    }
    if !seen.contains(hub) {
        bail!("mapped root repository {hub} has no catalog record");
    }
    for name in &survey.generated {
        if extension_usage_prefix(name) == Some(group) && !seen.contains(name.as_str()) {
            bail!("generated repository {name} has no catalog record");
        }
    }
    for name in seen {
        if !survey.generated.contains(name) {
            bail!("catalog repository {name} is absent from the generated inventory");
        }
    }
    Ok(group)
}

type RepoMapping = BTreeMap<String, String>;

struct BulkRepositories {
    by_canonical: HashMap<String, Repository>,
    complete: bool,
}

/// Resolve each hidden module through its apparent name in its parent's mapping. The
/// names predicted by `hidden_module_repo_names` alone cannot identify a bulk record.
fn verified_hidden_modules(
    graph: Option<&str>,
    root_mapping: &[u8],
    mappings: &BTreeMap<String, RepoMapping>,
    hidden: &BTreeMap<String, String>,
) -> bool {
    fn walk(
        node: &serde_json::Value,
        parent: &RepoMapping,
        mappings: &BTreeMap<String, RepoMapping>,
        hidden: &BTreeMap<String, String>,
        seen: &mut BTreeSet<String>,
    ) -> Option<()> {
        for child in node.get("dependencies")?.as_array()? {
            let key = child.get("key")?.as_str()?;
            let canonical = parent.get(child.get("apparentName")?.as_str()?)?;
            if let Some(expected) = hidden.get(key) {
                if expected != canonical {
                    return None;
                }
                seen.insert(key.to_owned());
            }
            if child
                .get("dependencies")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|dependencies| !dependencies.is_empty())
            {
                walk(child, mappings.get(canonical)?, mappings, hidden, seen)?;
            }
        }
        Some(())
    }
    if hidden.is_empty() || mappings.is_empty() {
        return false;
    }
    let Some(graph) = graph.and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
    else {
        return false;
    };
    let Ok(root) = serde_json::from_slice::<RepoMapping>(root_mapping) else {
        return false;
    };
    let mut seen = BTreeSet::new();
    walk(&graph, &root, mappings, hidden, &mut seen).is_some() && seen.len() == hidden.len()
}

/// Whether `canonical` names a repository a module extension generated rather than a module's
/// own repository: `rules_go++go_sdk+go_default_sdk`, `platforms+host_platform+host_platform`
/// or the root's `+ext+repo`, against `rules_go+`, `dep+1.0` and `platforms`.
fn is_extension_repo(canonical: &str) -> bool {
    canonical.matches('+').count() >= 2
}

/// The canonical prefix shared by repositories generated by one extension usage.
pub(crate) fn extension_usage_prefix(canonical: &str) -> Option<&str> {
    if !is_extension_repo(canonical) {
        return None;
    }
    canonical.rsplit_once('+').map(|(prefix, _repo)| prefix)
}

/// Finds the emitted defining module and its definition hash from an extension usage prefix.
/// Ordinary module canonicals include the module/version `+` separator, and those components
/// contain no `+`. Special bare names never have versioned forms, so emitted names cannot
/// nest at separator boundaries.
fn extension_repo_owner<'a>(
    usage_prefix: &str,
    module_definitions: &'a BTreeMap<String, String>,
) -> Option<(&'a String, &'a String)> {
    usage_prefix
        .match_indices('+')
        .find_map(|(separator, _matched)| {
            module_definitions.get_key_value(&usage_prefix[..separator])
        })
}

/// Upper bound on the bytes of repository names one `bazel mod` invocation is given, unless
/// [`MOD_ARGUMENT_BYTE_BUDGET_ENV`] says otherwise. Windows caps a command line at 32K
/// characters, and `cmd.exe` at [`CMD_EXE_COMMAND_LINE_LIMIT`], which is the one that binds
/// whenever a batch file is on the path to Bazel: a `--bazelPath` naming `bazel.bat`, or
/// Bazelisk running the workspace's `tools/bazel.bat` wrapper, which re-expands the whole
/// line through `"%BAZEL_REAL%" %*` (#536). 6K leaves the Bazel path, the startup options
/// and the subcommand their share of it. Elsewhere the limit is megabytes, but one
/// invocation per few thousand repositories keeps a workspace with tens of thousands of
/// extension repositories (an LLVM or pip hub per platform) away from it too.
const DEFAULT_MOD_ARGUMENT_BYTE_BUDGET: usize = if cfg!(windows) { 6 * 1024 } else { 256 * 1024 };

/// The longest command line `cmd.exe` runs.
const CMD_EXE_COMMAND_LINE_LIMIT: usize = 8191;

// The Windows default must leave `cmd.exe` room for everything but the names: at least a
// Bazel path, startup options and the `mod` subcommand's own arguments (#536).
const _: () = assert!(
    !cfg!(windows) || DEFAULT_MOD_ARGUMENT_BYTE_BUDGET + 2047 <= CMD_EXE_COMMAND_LINE_LIMIT
);

/// Environment variable overriding [`DEFAULT_MOD_ARGUMENT_BYTE_BUDGET`] with a byte count,
/// for a Bazel wrapper that leaves the names less room (long startup options) or more (no
/// batch file on Windows).
pub const MOD_ARGUMENT_BYTE_BUDGET_ENV: &str = "BAZEL_DIFF_MOD_ARGUMENT_BYTE_BUDGET";

fn mod_argument_byte_budget() -> usize {
    mod_argument_byte_budget_from(std::env::var(MOD_ARGUMENT_BYTE_BUDGET_ENV).ok().as_deref())
}

/// The byte budget `setting` (the environment variable's value) asks for, or the default when
/// it is unset or not a positive byte count.
fn mod_argument_byte_budget_from(setting: Option<&str>) -> usize {
    let Some(setting) = setting else {
        return DEFAULT_MOD_ARGUMENT_BYTE_BUDGET;
    };
    match setting.trim().parse::<usize>() {
        Ok(budget) if budget > 0 => budget,
        _ => {
            eprintln!(
                "[Warn] ignoring {MOD_ARGUMENT_BYTE_BUDGET_ENV}={setting:?}: not a positive byte count"
            );
            DEFAULT_MOD_ARGUMENT_BYTE_BUDGET
        }
    }
}

pub(crate) type NativeDefinitionRecorder<'a> = &'a mut dyn FnMut(&str, &Rule);

#[derive(Clone, Default)]
pub(crate) struct ScopedSources {
    pub(crate) repositories: BTreeSet<String>,
    pub(crate) repository_inputs: BTreeSet<String>,
    pub(crate) queried_files: HashSet<String>,
    /// None for caller-supplied query rows with no record of optional lookups.
    pub(crate) supplier_reads: Option<SupplierReads>,
}

#[derive(Clone, Default)]
pub(crate) struct SupplierReads {
    /// Exact roots of incomplete dependency or definition reads.
    pub(crate) incomplete: BTreeSet<String>,
    /// Reached rule whose own toolchain requirements were not reported.
    pub(crate) untyped_leaves: BTreeSet<String>,
    /// Ordinary alternatives of a native forwarder whose binding the walk left opaque.
    pub(crate) deferred_bindings: BTreeMap<String, BTreeSet<String>>,
    /// Canonical repository names reached by unresolved class inputs, keyed by
    /// the exact returned member name. These are transitive uncertainty only.
    pub(crate) uncertain_class_repositories: BTreeMap<String, BTreeSet<String>>,
    /// Native definitions used by acquisition but unavailable to direct hashing.
    pub(crate) unrecorded_definitions: BTreeSet<String>,
    /// Native identities whose full definitions contributed to direct hashing.
    pub(crate) verified_native: BTreeSet<String>,
}

/// Repository mapping and observations shared by supplemental queries in one generation.
struct RepositoryReadContext<'a> {
    mapping: &'a HashMap<String, String>,
    reads: &'a mut SupplierReads,
    /// Candidate names mapped to whether acquisition already observed a native identity.
    native_rules: BTreeMap<String, bool>,
}

impl RepositoryReadContext<'_> {
    fn candidate_native(&mut self, name: &str) {
        self.native_rules.entry(name.to_owned()).or_insert(false);
    }

    fn observed_native(&mut self, name: &str) {
        self.native_rules.insert(name.to_owned(), true);
    }

    fn defer_binding(&mut self, rule: &Rule, attribute: Option<&Attribute>) {
        let mapping = self.mapping;
        let id = canonical_query_label(&rule.name, mapping).into_owned();
        self.reads.incomplete.insert(id.clone());
        let inputs = self.reads.deferred_bindings.entry(id).or_default();
        let ordinary: BTreeSet<_> = rule
            .rule_input
            .iter()
            .map(|label| canonical_query_label(label, mapping).into_owned())
            .collect();
        if let Some(attribute) = attribute {
            // Record possible values without requesting either select branch. The
            // select key is a condition, not the supplier of the forwarded value.
            let alternatives = attribute
                .selector_list
                .as_option()
                .into_iter()
                .flat_map(|list| &list.elements)
                .flat_map(|selector| &selector.entries)
                .flat_map(|entry| entry.string_value.iter().chain(&entry.string_list_value));
            for value in attribute
                .string_value
                .iter()
                .chain(&attribute.string_list_value)
                .chain(alternatives)
            {
                let value = canonical_query_label(value, mapping).into_owned();
                if ordinary.contains(&value) {
                    inputs.insert(value);
                }
            }
        } else {
            // A failed structural read only supplied the ordinary inputs.
            inputs.extend(ordinary);
        }
    }

    fn incomplete<'a>(&mut self, names: impl IntoIterator<Item = &'a String>) {
        let mapping = self.mapping;
        self.reads.incomplete.extend(
            names
                .into_iter()
                .map(|name| canonical_query_label(name, mapping).into_owned()),
        );
    }
}

/// Bazel serializes the native toolchain rule's LABEL_LIST normally and its
/// NODEP_LABEL_LIST as STRING_LIST with nodep=true. A select retains that element type.
fn declaration_target_settings(attribute: &Attribute) -> Option<Vec<&str>> {
    use crate::proto::blaze_query::attribute::Discriminator;
    let expected = if attribute.nodep == Some(true) {
        Discriminator::StringList
    } else {
        Discriminator::LabelList
    };
    let values: Vec<_> = if attribute.r#type == expected {
        attribute
            .string_list_value
            .iter()
            .map(String::as_str)
            .collect()
    } else if attribute.r#type == Discriminator::SelectorList {
        let select = attribute.selector_list.as_option()?;
        if !select.r#type.is_some_and(|kind| kind == expected) {
            return None;
        }
        select
            .elements
            .iter()
            .flat_map(|element| &element.entries)
            .flat_map(|entry| &entry.string_list_value)
            .map(String::as_str)
            .collect()
    } else {
        return None;
    };
    values
        .iter()
        .all(|value| !value.is_empty() && !value.starts_with("@@["))
        .then_some(values)
}

fn structural_labels(attribute: &Attribute) -> impl Iterator<Item = &String> {
    attribute.string_value.iter().chain(
        attribute
            .selector_list
            .as_option()
            .into_iter()
            .flat_map(|list| &list.elements)
            .flat_map(|selector| &selector.entries)
            .filter_map(|entry| entry.string_value.as_ref()),
    )
}

fn alias_leaves(
    label: &str,
    aliases: &BTreeMap<String, Vec<String>>,
    leaves: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut reached = alias_closure(vec![label.to_owned()], aliases);
    reached.retain(|candidate| leaves.contains(candidate));
    reached
}

fn alias_closure(
    mut work: Vec<String>,
    aliases: &BTreeMap<String, Vec<String>>,
) -> BTreeSet<String> {
    let mut checked = BTreeSet::new();
    while let Some(next) = work.pop() {
        if checked.insert(next.clone()) {
            if let Some(children) = aliases.get(&next) {
                work.extend(children.iter().cloned());
            }
        }
    }
    checked
}

/// Ordered canonical MODULE registration targets from a complete successful producer result.
/// This excludes configuration, platform and transition additions and target_settings filtering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ModuleToolchainRegistrations {
    pub(crate) labels: Vec<String>,
}

impl ModuleToolchainRegistrations {
    fn from_graph(graph: &serde_json::Value) -> Option<Self> {
        let registrations = graph.get("moduleToolchainRegistrations")?.as_array()?;
        let mut seen = HashSet::new();
        let labels = registrations
            .iter()
            .map(|value| {
                let label = value.as_str()?;
                let canonical = label
                    .strip_prefix("//")
                    .is_some_and(|target| !target.is_empty())
                    || label
                        .strip_prefix("@@")
                        .and_then(|label| label.split_once("//"))
                        .is_some_and(|(repo, target)| !repo.is_empty() && !target.is_empty());
                if !canonical || !seen.insert(label) {
                    return None;
                }
                Some(label.to_owned())
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { labels })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RepositoryTraversal<'a> {
    Ordinary,
    Conditions,
    ProviderLiterals,
    ReaderLiterals(&'a BTreeSet<String>),
}

impl RepositoryTraversal<'_> {
    fn is_literal(self) -> bool {
        matches!(self, Self::ProviderLiterals | Self::ReaderLiterals(_))
    }

    fn is_reader(self) -> bool {
        matches!(self, Self::ReaderLiterals(_))
    }
}

pub(crate) struct LiteralToolchainRows {
    pub(crate) rows: Vec<Target>,
    /// The literal query completed normally, without an error diagnostic. Callers
    /// still need to check that the particular target and inputs they use exist.
    pub(crate) complete: bool,
}

/// Loading facts about MODULE registrations. This does not cover platform flags,
/// extra_toolchains, configured compatibility, or selected execution groups.
#[derive(Default)]
pub(crate) struct StaticToolchains {
    pub(crate) registration_order: Vec<String>,
    /// Source files and actual package groups verified by a strict literal read.
    pub(crate) non_reader_inputs: BTreeSet<String>,
    /// Actual bindings of already-returned local registration aliases. A
    /// failed strict read keeps only a conservative ordinary-input witness.
    pub(crate) local_registration_aliases: BTreeMap<String, Vec<String>>,

    /// Eligibility labels evaluated separately from the declaration in the consumer's configuration.
    pub(crate) nodep_settings: BTreeMap<String, BTreeSet<String>>,
    /// Settings of unregistered declarations named by ordinary returned rules.
    local_setting_inputs: BTreeSet<String>,
    /// Native declaration labels and their NODEP implementation alternatives.
    pub(crate) declarations: BTreeMap<String, StaticToolchainDeclaration>,
    /// Alias and declaration rows on positively observed registration paths.
    pub(crate) registration_paths: BTreeMap<String, RegistrationPath>,
    /// Actual alias and native toolchain_type rows joining each required type to
    /// its registered declarations. Equal keys can match without a physical row.
    pub(crate) type_paths: BTreeMap<String, BTreeSet<String>>,
    /// Each literal registration alias and type alias keeps its own destinations.
    pub(crate) aliases: BTreeMap<String, Vec<String>>,
    /// Contributions to a rule's direct hash, separately named so an explicitly
    /// ignored attribute stays ignored. Structural graph edges are kept separately.
    pub(crate) bindings: BTreeMap<String, Vec<(&'static str, [u8; 32])>>,
    /// Ordered registration literals, not the final declaration after alias expansion.
    pub(crate) by_type: BTreeMap<String, Vec<String>>,
    /// Unavailable or structurally unverifiable declaration/type labels.
    pub(crate) unresolved: BTreeSet<String>,
    native_types: BTreeSet<String>,
}
pub(crate) struct StaticToolchainDeclaration {
    pub(crate) ty: String,
    pub(crate) implementations: BTreeSet<String>,
    /// Ordinary inputs actually reported on the declaration.
    pub(crate) ordinary_inputs: BTreeSet<String>,
}
#[derive(Clone, Default)]
pub(crate) struct RegistrationPath {
    pub(crate) aliases: BTreeSet<String>,
    pub(crate) declarations: BTreeSet<String>,
}

impl StaticToolchains {
    /// Equal canonical type spellings match directly. An alias additionally
    /// matches the native toolchain_type leaves found in its returned branches.
    pub(crate) fn possible_type_keys(&self, ty: &str) -> BTreeSet<String> {
        let mut keys = alias_leaves(ty, &self.aliases, &self.native_types);
        keys.insert(ty.to_owned());
        keys
    }

    /// A configurable registered alias can name declarations of different types.
    /// Keep only branches that lead to a declaration matching this requirement.
    pub(crate) fn registration_path_for(
        &self,
        required: &str,
        registration: &str,
    ) -> Option<Cow<'_, RegistrationPath>> {
        let path = self.registration_paths.get(registration)?;
        let types = self.type_paths.get(required)?;
        let matches = |name: &String| {
            let ty = &self.declarations[name].ty;
            ty == required || types.contains(ty)
        };
        if path.declarations.is_empty() {
            return None;
        }
        if path.declarations.iter().all(matches) {
            return Some(Cow::Borrowed(path));
        }
        let declarations: BTreeSet<_> = path
            .declarations
            .iter()
            .filter(|name| matches(name))
            .cloned()
            .collect();
        if declarations.is_empty() {
            return None;
        }
        let mut aliases = self.observed_path(registration, &declarations);
        aliases.retain(|name| !declarations.contains(name));
        Some(Cow::Owned(RegistrationPath {
            declarations,
            aliases,
        }))
    }

    fn observed_path(&self, literal: &str, leaves: &BTreeSet<String>) -> BTreeSet<String> {
        if leaves.is_empty() {
            return BTreeSet::new();
        }
        // In an acyclic graph keep both parents of a diamond. In an unresolved
        // cycle keep witness prefixes and cut edges back to active ancestors.
        let mut seen = BTreeSet::from([literal]);
        let mut active = seen.clone();
        let mut stack = vec![(literal, 0)];
        let mut parents = BTreeMap::<&str, Vec<&str>>::new();
        while let Some((label, next)) = stack.last_mut() {
            let label = *label;
            let Some(child) = self
                .aliases
                .get(label)
                .and_then(|children| children.get(*next))
            else {
                active.remove(label);
                stack.pop();
                continue;
            };
            *next += 1;
            let child = child.as_str();
            if active.contains(child) {
                continue;
            }
            parents.entry(child).or_default().push(label);
            if seen.insert(child) {
                active.insert(child);
                stack.push((child, 0));
            }
        }
        let mut path = BTreeSet::new();
        let mut pending: Vec<_> = seen
            .into_iter()
            .filter(|name| leaves.contains(*name))
            .collect();
        while let Some(label) = pending.pop() {
            if path.insert(label.to_owned()) {
                pending.extend(parents.get(label).into_iter().flatten().copied());
            }
        }
        path
    }

    pub(crate) fn declaration_forwarders(&self) -> BTreeSet<String> {
        let declarations = self.declarations.keys().cloned().collect();
        closed_aliases(
            self.aliases.iter().chain(&self.local_registration_aliases),
            &declarations,
            &self.unresolved,
        )
    }

    fn index_types(&mut self, required: &BTreeSet<String>) {
        let known: BTreeSet<_> = self.declarations.keys().cloned().collect();
        let complete_registrations = closed_aliases(&self.aliases, &known, &self.unresolved);
        self.unresolved.extend(
            self.registration_order
                .iter()
                .filter(|s| !complete_registrations.contains(*s))
                .cloned(),
        );
        let complete_types = closed_aliases(&self.aliases, &self.native_types, &self.unresolved);
        self.unresolved.extend(
            required
                .iter()
                .chain(self.declarations.values().map(|d| &d.ty))
                .filter(|s| !complete_types.contains(*s))
                .cloned(),
        );
        let mut ordered = BTreeMap::<String, Vec<String>>::new();
        let mut type_spellings = BTreeMap::<String, BTreeSet<String>>::new();
        for registration in &self.registration_order {
            let (declarations, aliases) = self
                .observed_path(registration, &known)
                .into_iter()
                .partition(|name| known.contains(name));
            let path = RegistrationPath {
                aliases,
                declarations,
            };
            let mut types = BTreeSet::new();
            for label in &path.declarations {
                let declaration = &self.declarations[label];
                if !complete_types.contains(&declaration.ty) {
                    self.unresolved.insert(registration.clone());
                }
                // Equal canonical keys can be joined even if the toolchain_type row
                // itself was not in the ordinary target set.
                types.insert(declaration.ty.clone());
                for leaf in alias_leaves(&declaration.ty, &self.aliases, &self.native_types) {
                    type_spellings
                        .entry(leaf.clone())
                        .or_default()
                        .insert(declaration.ty.clone());
                    types.insert(leaf);
                }
            }
            for ty in types {
                ordered.entry(ty).or_default().push(registration.clone());
            }
            self.registration_paths.insert(registration.clone(), path);
        }
        for ty in required {
            let mut family = alias_leaves(ty, &self.aliases, &self.native_types);
            let active: BTreeSet<_> = family
                .iter()
                .filter(|leaf| type_spellings.contains_key(*leaf))
                .cloned()
                .collect();
            let mut nodes = self.observed_path(ty, &active);
            let spellings: BTreeSet<_> = active
                .iter()
                .filter_map(|leaf| type_spellings.get(leaf))
                .flatten()
                .collect();
            for spelling in spellings {
                nodes.extend(self.observed_path(spelling, &active));
            }
            self.type_paths.insert(ty.clone(), nodes);
            family.insert(ty.clone());
            let literals: BTreeSet<_> = family
                .iter()
                .filter_map(|key| ordered.get(key))
                .flatten()
                .collect();
            let labels = self
                .registration_order
                .iter()
                .filter(|label| literals.contains(label))
                .cloned()
                .collect();
            self.by_type.insert(ty.clone(), labels);
        }
    }
}

/// An alias with an unavailable branch or an unresolved cycle can still have a
/// known alternative. It must not be advertised as a fully verified binding.
fn closed_aliases<'a>(
    aliases: impl IntoIterator<Item = (&'a String, &'a Vec<String>)>,
    leaves: &BTreeSet<String>,
    blocked: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut parents = BTreeMap::<&str, Vec<&str>>::new();
    let mut pending = BTreeMap::new();
    for (alias, inputs) in aliases {
        if blocked.contains(alias) {
            continue;
        }
        pending.insert(alias.as_str(), inputs.len());
        for input in inputs {
            parents.entry(input.as_str()).or_default().push(alias);
        }
    }
    let mut known: BTreeSet<_> = leaves.difference(blocked).cloned().collect();
    let mut work: Vec<_> = leaves.difference(blocked).map(String::as_str).collect();
    while let Some(label) = work.pop() {
        for &parent in parents.get(label).into_iter().flatten() {
            let count = pending.get_mut(parent).expect("indexed alias");
            *count -= 1;
            if *count == 0 && known.insert(parent.to_owned()) {
                work.push(parent);
            }
        }
    }
    known
}

/// Targets with the accepted module graph and successful unfiltered root mapping from discovery.
pub(crate) struct QueriedTargets {
    pub(crate) direct_toolchain_inputs: bool,
    pub(crate) targets: Vec<Target>,
    pub(crate) module_graph_json: Option<String>,
    pub(crate) root_mapping: Option<Vec<u8>>,
    pub(crate) static_toolchains: Option<StaticToolchains>,
    pub(crate) scoped_sources: ScopedSources,
    /// The output base `bazel info` reported before the query, when it was asked.
    pub(crate) output_base: Option<PathBuf>,
}

/// The repositories `bazel mod` describes for a Bzlmod workspace, lowered to `//external:`
/// nodes, with what it could not describe.
#[derive(Default)]
struct BzlmodRepos {
    targets: Vec<Target>,
    /// Canonical names from RepoSpecs actually returned by Bazel.
    shown_repositories: BTreeSet<String>,
    scope: IsolatedRepoScope,
    /// Extension diagnostics and canonical repositories whose mappings failed.
    failed_extensions: FailedExtensions,
    /// The root module's repository mapping, canonical name -> apparent names.
    canonical_to_apparent: BTreeMap<String, Vec<String>>,
    /// The accepted module graph, shared by repository edges and hash-file metadata.
    module_graph_json: Option<String>,
    toolchain_registrations: Option<ModuleToolchainRegistrations>,
    /// Unfiltered stdout from a successful initial Bzlmod probe, shared with external hashing.
    root_mapping: Option<Vec<u8>>,
}

/// Extension diagnostics and the canonical repositories whose mappings actually failed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FailedExtensions {
    /// Bazel reported an extension failure, even if its diagnostic had no parseable ID.
    observed: bool,
    /// Extension ids printed by Bazel.
    extensions: BTreeSet<String>,
    /// Canonical repository names whose mapping keys failed.
    unavailable: BTreeSet<String>,
}

impl FailedExtensions {
    fn is_empty(&self) -> bool {
        !self.observed && self.extensions.is_empty() && self.unavailable.is_empty()
    }
}

/// What a failed `bazel mod` invocation said about module extensions.
struct ExtensionFailure {
    /// The extensions Bazel could not evaluate, by the id it prints.
    extensions: BTreeSet<String>,
    /// Whether Bazel still answered for the repositories that do not need them. It does when
    /// the extensions merely sit in the dependency graph, ending with `Results may be
    /// incomplete as N extensions failed.`; not when one of their repositories was asked for.
    answered: bool,
}

/// The line `bazel mod` ends with when it answered despite a module extension failing.
const EXTENSION_FAILURE_MARKER: &str = "Results may be incomplete as";

/// Reads a failed `bazel mod` invocation's stderr for module extensions it could not
/// evaluate. It retains ids printed as `@@<repo>//<package>:<file>.bzl%<name>` and also
/// recognizes the partial-answer marker when no id is present. `None` when neither is found.
fn extension_failure(stderr: &str) -> Option<ExtensionFailure> {
    let answered = stderr.contains(EXTENSION_FAILURE_MARKER);
    let extensions = stderr
        .lines()
        .filter(|line| line.contains("module extension"))
        .flat_map(str::split_whitespace)
        .filter(|word| word.starts_with("@@") && word.contains("//") && word.contains('%'))
        .map(|word| word.trim_end_matches(['.', ',', ';', ':']).to_owned())
        .collect::<BTreeSet<_>>();
    (answered || !extensions.is_empty()).then_some(ExtensionFailure {
        extensions,
        answered,
    })
}

fn has_unavailable_mapping(canonical: &str, failed: &FailedExtensions) -> bool {
    failed
        .unavailable
        .contains(canonical.trim_start_matches('@'))
}

/// Splits `arguments` into consecutive runs of at most `budget` bytes (separators included),
/// every run non-empty.
fn chunk_arguments(arguments: &[String], budget: usize) -> Vec<&[String]> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut bytes = 0;
    for (index, argument) in arguments.iter().enumerate() {
        let cost = argument.len() + 1;
        if index > start && bytes + cost > budget {
            chunks.push(&arguments[start..index]);
            start = index;
            bytes = 0;
        }
        bytes += cost;
    }
    if start < arguments.len() {
        chunks.push(&arguments[start..]);
    }
    chunks
}

pub(crate) type RepositoryInputs = Arc<RepositoryInputGroup>;

// '!' is outside Bazel's repository-name alphabet.

pub(crate) const IMPORT_FALLBACK_PREFIX: &str = "//external:!unresolved-import-";
pub(crate) const MODULE_FALLBACK_PREFIX: &str = "//external:!unresolved-module-";

fn repository_fallback_identity(name: &str) -> Option<(&str, &str)> {
    name.strip_prefix(IMPORT_FALLBACK_PREFIX)
        .or_else(|| name.strip_prefix(MODULE_FALLBACK_PREFIX))?
        .split_once('!')
}

pub(crate) fn is_repository_fallback(name: &str) -> bool {
    repository_fallback_identity(name).is_some()
}

pub(crate) fn repository_fallbacks(
    targets: &[Target],
    fine: &BTreeSet<String>,
) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for row in targets {
        let Some(name) = target_name(row) else {
            continue;
        };
        let Some((canonical, apparent)) = repository_fallback_identity(name) else {
            continue;
        };
        let own = format!("@{apparent}");
        let known = format!("@@{canonical}");
        if fine.contains(&own)
            || fine.contains(&known)
            || fine.contains(apparent)
            || fine.contains(canonical)
        {
            continue;
        }
        result.insert(own, name.to_owned());
        result.entry(known).or_insert_with(|| name.to_owned());
    }
    result
}

pub(crate) fn repository_fallback<'a>(
    label: &str,
    fallbacks: &'a HashMap<String, String>,
) -> Option<&'a String> {
    fallbacks.get(label.split_once("//")?.0)
}

pub(crate) struct RepositoryInputGroup {
    pub(crate) extension: String,
    pub(crate) labels: Vec<String>,
}

#[cfg(test)]
fn materialize_repository_inputs_for_batch(batch: &mut [Target], inputs: Option<RepositoryInputs>) {
    if let Some(inputs) = inputs {
        for target in batch {
            materialize_repository_inputs(target, Some(inputs.clone()));
        }
    }
}

#[cfg(test)]
fn materialize_repository_inputs(target: &mut Target, shared: Option<RepositoryInputs>) {
    if let Some(inputs) = shared {
        target.rule.as_option_mut().unwrap().rule_input = inputs.labels.clone();
    }
}

fn lower_repositories(
    mut repositories: Vec<Repository>,
    canonical_to_apparent: &BTreeMap<String, Vec<String>>,
    module_edges: &BTreeMap<String, BTreeSet<String>>,
    extension_edges: Option<&BTreeSet<String>>,
    label_only: &LabelOnlyRepositories,
    workspace: &Path,
    transform: &mut impl FnMut(&mut Target, Option<RepositoryInputs>),
) -> Vec<Target> {
    let workspace = RepositoryWorkspace::new(workspace);
    // A module the root cannot see has no apparent name there; its node is named by canonical
    // name, matching the `apparent_names` fallback below.
    let node_names = |canonical: &str| {
        canonical_to_apparent
            .get(canonical)
            .cloned()
            .unwrap_or_else(|| vec![canonical.to_owned()])
    };
    let module_to_canonical = repositories
        .iter()
        .filter_map(|repository| {
            let canonical = repository.canonical_name.as_deref()?;
            (canonical.matches('+').count() == 1)
                .then(|| (canonical.split('+').next().unwrap_or(canonical), canonical))
        })
        .map(|(module, canonical)| (module.to_owned(), canonical.to_owned()))
        .collect::<BTreeMap<_, _>>();

    // An extension's repositories are built by the owning module's extension code, from tags
    // the owning module's definition shapes, so that definition -- attributes, override patches,
    // a local override's tree -- is folded into each of them as an attribute: a patched
    // `rules_rs` is a different `@rules_rust` and `@bd_crates`, which is how a target that never
    // names `@rules_rs//` sees the patch. An attribute rather than an edge, so the query-mode
    // edges from a module to its extension repositories below do not close a cycle.
    // The same record supplies the module definition and its synthetic rule. Use the record's
    // position, since separate records with the same canonical name may have different inputs.
    let mut module_files = HashMap::new();
    let mut module_definitions = BTreeMap::new();
    for (index, repository) in repositories.iter_mut().enumerate() {
        let Some(name) = &repository.canonical_name else {
            continue;
        };
        if !is_extension_repo(name) {
            let name = name.clone();
            let files = prepare_repository(repository, &workspace);
            module_definitions.insert(name, repository_definition_hash(repository, &files));
            module_files.insert(index, files);
        }
    }

    // Query mode can omit resolved toolchains and targets outside the queried repositories.
    // Generated inventories are fallback inputs, separate from module definitions and declared
    // module dependencies. Hashing uses them for unresolved readers; verified ordinary labels
    // follow their actual targets. This retains the hidden SDK and hub fallbacks from #529.
    // An extension listed in `label_only_module_extensions` contributes no owner fallback inputs:
    // the caller asserts that its repositories are reached only through labels. Other extension
    // usages and the imported-repository fallbacks retain their existing contracts (#603).
    let mut module_extension_repos = BTreeMap::<String, BTreeSet<String>>::new();
    let mut extension_spokes = BTreeMap::<String, BTreeSet<String>>::new();
    if let Some(imported) = extension_edges {
        for repository in &repositories {
            let canonical = repository.canonical_name.as_deref().unwrap_or_default();
            let Some(extension) = extension_usage_prefix(canonical) else {
                continue;
            };
            if let Some((module_repo, _definition_hash)) =
                extension_repo_owner(extension, &module_definitions).filter(
                    |(module_repo, _definition_hash)| {
                        !module_repo.is_empty()
                            && !label_only.owner_exemptions.contains(canonical)
                            && !label_only.extensions.contains(extension)
                    },
                )
            {
                module_extension_repos
                    .entry(module_repo.clone())
                    .or_default()
                    .extend(node_names(canonical));
            }
            if !imported.contains(canonical) {
                extension_spokes
                    .entry(extension.to_owned())
                    .or_default()
                    .extend(node_names(canonical));
            }
        }
    }

    let module_dependencies = module_to_canonical
        .iter()
        .map(|(module, canonical)| {
            let dependencies = module_edges
                .get(module)
                .into_iter()
                .flatten()
                .filter_map(|dependency| module_to_canonical.get(dependency))
                .cloned()
                .collect::<BTreeSet<_>>();
            (canonical.clone(), dependencies)
        })
        .collect::<BTreeMap<_, _>>();
    // A module's unresolved reader previously reached generated repositories through
    // its declared module dependencies too. Keep that relation among fallback nodes.
    let mut parents = HashMap::<&str, Vec<&str>>::new();
    for (module, dependencies) in &module_dependencies {
        for dependency in dependencies {
            parents
                .entry(dependency.as_str())
                .or_default()
                .push(module.as_str());
        }
    }
    let mut fallback_modules = HashSet::new();
    let mut pending: Vec<_> = module_extension_repos.keys().map(String::as_str).collect();
    while let Some(module) = pending.pop() {
        if fallback_modules.insert(module) {
            if let Some(ancestors) = parents.get(module) {
                pending.extend(ancestors);
            }
        }
    }

    let mut targets = Vec::new();
    let mut shared_groups = HashMap::<String, RepositoryInputs>::new();
    let empty = BTreeSet::new();
    for (index, mut repository) in repositories.into_iter().enumerate() {
        let canonical = repository.canonical_name.as_deref().unwrap_or_default();
        let extension = extension_usage_prefix(canonical);
        let owner_definition_hash = extension
            .and_then(|extension| extension_repo_owner(extension, &module_definitions))
            .map(|(_module_repo, definition_hash)| definition_hash.as_str());
        let mut dependencies = module_dependencies
            .get(canonical)
            .into_iter()
            .flatten()
            .flat_map(|canonical| node_names(canonical))
            .collect::<BTreeSet<_>>();
        let module_fallback = fallback_modules.contains(canonical).then(|| {
            let mut inputs = module_extension_repos
                .get(canonical)
                .into_iter()
                .flatten()
                .map(|name| format!("//external:{name}"))
                .collect::<BTreeSet<_>>();
            for dependency in module_dependencies.get(canonical).into_iter().flatten() {
                if fallback_modules.contains(dependency.as_str()) {
                    inputs.extend(node_names(dependency).into_iter().map(|apparent| {
                        format!("{MODULE_FALLBACK_PREFIX}{dependency}!{apparent}")
                    }));
                }
            }
            (canonical.to_owned(), inputs)
        });
        let spokes = extension
            .filter(|_| extension_edges.is_some_and(|imported| imported.contains(canonical)))
            .and_then(|extension| extension_spokes.get_key_value(extension));
        let group = if dependencies.is_empty() {
            spokes
        } else {
            if let Some((_, names)) = spokes {
                dependencies.extend(names.iter().cloned());
            }
            None
        };
        let names = node_names(canonical);
        if names.is_empty() {
            continue;
        }
        let group_identity =
            (!label_only.owner_exemptions.contains(canonical)).then(|| canonical.to_owned());
        let files = module_files
            .remove(&index)
            .unwrap_or_else(|| prepare_repository(&mut repository, &workspace));
        let rule = repository_rule(repository, files, owner_definition_hash);
        // All apparent names have the same definition. Move it into the final output.
        let mut rules = std::iter::repeat_n(rule, names.len());
        for apparent in names {
            // Imported hubs of one extension share its ordered hidden siblings. Pass
            // the same allocation to the hash traversal when no owner-specific edge
            // needs adding or removing. Raw query callers expand it into the protobuf.
            let (inputs, shared) = match group {
                Some((extension, names)) if !names.contains(&apparent) => {
                    let shared = shared_groups.entry(extension.clone()).or_insert_with(|| {
                        Arc::new(RepositoryInputGroup {
                            extension: extension.clone(),
                            labels: names
                                .iter()
                                .map(|name| format!("//external:{name}"))
                                .collect(),
                        })
                    });
                    (&empty, Some(Arc::clone(shared)))
                }
                Some((_, names)) => (names, None),
                None => (&dependencies, None),
            };
            let mut target = repository_target(rules.next().unwrap(), &apparent, inputs);
            if let Some((canonical, inputs)) = &module_fallback {
                let mut fallback = Target {
                    r#type: target::Discriminator::Rule,
                    rule: buffa::MessageField::some(Rule {
                        name: format!("{MODULE_FALLBACK_PREFIX}{canonical}!{apparent}"),
                        rule_class: "_bazel_diff_unresolved_module".to_owned(),
                        rule_input: inputs.iter().cloned().collect(),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                transform(&mut fallback, None);
                targets.push(fallback);
            }
            match (shared, group_identity.as_deref()) {
                (Some(group), Some(canonical)) => {
                    let mut fallback = Target {
                        r#type: target::Discriminator::Rule,
                        rule: buffa::MessageField::some(Rule {
                            name: format!("{IMPORT_FALLBACK_PREFIX}{canonical}!{apparent}"),
                            rule_class: "_bazel_diff_unresolved_import".to_owned(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    };
                    transform(&mut fallback, Some(group));
                    targets.push(fallback);
                    transform(&mut target, None);
                }
                (shared, _) => transform(&mut target, shared),
            }
            targets.push(target);
        }
    }
    targets
}

fn parse_bazel_version(text: &str) -> Option<BazelVersion> {
    let version = text.lines().find_map(|line| {
        line.strip_prefix("Build label: ")
            .or_else(|| line.strip_prefix("bazel "))
    })?;
    let mut parts = version
        .split('-')
        .next()
        .unwrap_or(version)
        .split('.')
        .map(|part| {
            part.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<u32>()
                .unwrap_or(0)
        });
    Some(BazelVersion(
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    ))
}

/// Parses `bazel info release output_base starlark-semantics`. `None` unless every key is there.
fn parse_server_info(text: &str) -> Option<ServerInfo> {
    let mut release = None;
    let mut output_base = None;
    let mut semantics = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(": ") else {
            continue;
        };
        match key {
            "release" => release = Some(value.trim()),
            "output_base" => output_base = Some(PathBuf::from(value.trim())),
            "starlark-semantics" => semantics = Some(value.trim()),
            _ => {}
        }
    }
    let (release, output_base, semantics) = (release?, output_base?, semantics?);
    // `release 8.8.2`, or `development version` for a source build, whose version stays unknown.
    let version = release
        .strip_prefix("release ")
        .filter(|version| version.starts_with(|c: char| c.is_ascii_digit()))
        .and_then(|version| parse_bazel_version(&format!("bazel {version}")));
    // The semantics print only flags that differ from their defaults: WORKSPACE is on by default
    // before Bazel 8, off from 8 on, and gone in 9.
    let external_package = if semantics.contains("enable_workspace=true") {
        Some(true)
    } else if semantics.contains("enable_workspace=false") {
        Some(false)
    } else {
        version.map(|version| version < BazelVersion(8, 0, 0))
    };
    Some(ServerInfo {
        version,
        output_base: Some(output_base),
        external_package,
    })
}

fn is_external_package_error(message: &str) -> bool {
    message.contains("no such package 'external'")
        || message.contains("//external package is not available")
}

fn deduplicate_targets(mut targets: Vec<Target>) -> Result<Vec<Target>> {
    // Decide which targets to keep while their names can still be borrowed.
    let mut keep = {
        let mut seen = HashSet::new();
        targets
            .iter()
            .map(|target| target_name(target).is_some_and(|name| seen.insert(name)))
            .collect::<Vec<_>>()
            .into_iter()
    };
    targets.retain(|_| keep.next().expect("one decision per target"));
    Ok(targets)
}

pub fn decode_delimited<M: Message>(path: &Path) -> Result<Vec<M>> {
    let mut reader = BufReader::with_capacity(1 << 20, File::open(path)?);
    let mut batch = RawBatch::default();
    let mut messages = Vec::new();
    let mut decoded = Vec::new();
    while read_raw_batch(&mut reader, &mut batch)? {
        batch
            .slices()
            .map(|bytes| buffa::DecodeOptions::new().decode_from_slice::<M>(bytes))
            .collect_into_vec(&mut decoded);
        messages.reserve(decoded.len());
        for message in decoded.drain(..) {
            messages.push(message?);
        }
    }
    Ok(messages)
}

/// Upper bounds on one decode batch. Batching keeps peak memory proportional to
/// the batch rather than to the whole query output, which for a large workspace
/// is gigabytes.
///
/// A decoded rule still carries every attribute (implicit ones included, several
/// hundred bytes each) until the batch transform prehashes and drops them, so the
/// message bound sets most of the decode peak. On the large perf-proof workload,
/// 8192 instead of 1024 raised generate-hashes' peak RSS from about 160 to 245 MiB;
/// below 1024 the peak no longer moves, and each batch stays large enough to decode
/// in parallel.
const DECODE_BATCH_MESSAGES: usize = 1024;
const DECODE_BATCH_BYTES: usize = 32 * 1024 * 1024;

/// Raw, still-encoded messages read off the stream, kept in one contiguous
/// buffer so a batch costs one allocation rather than one per message.
#[derive(Default)]
struct RawBatch {
    buffer: Vec<u8>,
    bounds: Vec<(usize, usize)>,
}

impl RawBatch {
    fn clear(&mut self) {
        self.buffer.clear();
        self.bounds.clear();
    }

    fn slices(&self) -> impl IndexedParallelIterator<Item = &[u8]> {
        self.bounds
            .par_iter()
            .map(|(start, end)| &self.buffer[*start..*end])
    }
}

/// Reads a length-delimited varint prefix, returning `None` at end of stream.
fn read_message_length(reader: &mut impl BufRead) -> Result<Option<usize>> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let available = reader.fill_buf()?;
        let Some(byte) = available.first().copied() else {
            if shift == 0 {
                return Ok(None);
            }
            bail!("truncated length prefix in Bazel query output");
        };
        reader.consume(1);
        if shift == 63 && byte > 1 {
            bail!("length prefix in Bazel query output overflows a u64");
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if value > u64::from(buffa::message::MAX_MESSAGE_BYTES) {
                bail!("message exceeds the protobuf size limit");
            }
            return usize::try_from(value)
                .map(Some)
                .map_err(|_| anyhow!("length prefix {value} does not fit in usize"));
        }
        shift += 7;
    }
}

/// Fills `batch` with up to the batch limits worth of encoded messages,
/// returning false once the stream is exhausted.
fn read_raw_batch(reader: &mut impl BufRead, batch: &mut RawBatch) -> Result<bool> {
    batch.clear();
    while batch.bounds.len() < DECODE_BATCH_MESSAGES && batch.buffer.len() < DECODE_BATCH_BYTES {
        let Some(length) = read_message_length(reader)? else {
            break;
        };
        let start = batch.buffer.len();
        // Grow with bytes actually delivered if the stream declares a large frame.
        batch.buffer.reserve(length.min(64 * 1024));
        let copied = std::io::copy(
            &mut reader.take(length as u64),
            &mut &mut batch.buffer as &mut dyn std::io::Write,
        )?;
        if copied != length as u64 {
            bail!("truncated message in Bazel query output");
        }
        batch.bounds.push((start, batch.buffer.len()));
    }
    Ok(!batch.bounds.is_empty())
}

#[cfg(test)]
fn decode_target_stream(
    path: &Path,
    transform: &mut impl FnMut(&mut [Target]),
) -> Result<Vec<Target>> {
    decode_target_stream_filtered(path, transform, |_| true, false)
}

fn decode_target_stream_filtered(
    path: &Path,
    transform: &mut impl FnMut(&mut [Target]),
    mut retain: impl FnMut(&Target) -> bool,
    keep_class_keys: bool,
) -> Result<Vec<Target>> {
    let mut reader = BufReader::with_capacity(1 << 20, File::open(path)?);
    let mut targets = Vec::new();
    let mut batch = RawBatch::default();
    let mut decoded = Vec::new();
    while read_raw_batch(&mut reader, &mut batch)? {
        batch
            .slices()
            .map(|bytes| {
                <Target as Message>::decode_from_slice(bytes)
                    .map_err(anyhow::Error::from)
                    .map(|target| lower_target_with_class_keys(target, keep_class_keys))
            })
            .collect_into_vec(&mut decoded);
        let start = targets.len();
        targets.reserve(decoded.len());
        for lowered in decoded.drain(..) {
            if let Some(target) = lowered?.filter(&mut retain) {
                targets.push(target);
            }
        }
        transform(&mut targets[start..]);
    }
    Ok(targets)
}

fn decode_cquery_stream(
    path: &Path,
    streamed: bool,
    transform: &mut impl FnMut(&mut [Target]),
) -> Result<Vec<Target>> {
    let mut decoder = CqueryDecoder::default();
    if streamed {
        // Results decode in parallel, a raw batch at a time; naming them stays in stream order
        // because a result's configuration may be defined by an earlier message.
        let mut reader = BufReader::with_capacity(1 << 20, File::open(path)?);
        let mut batch = RawBatch::default();
        let mut decoded = Vec::new();
        while read_raw_batch(&mut reader, &mut batch)? {
            batch
                .slices()
                .map(|bytes| CqueryResult::decode_from_slice(bytes).map_err(anyhow::Error::from))
                .collect_into_vec(&mut decoded);
            for result in decoded.drain(..) {
                decoder.push(result?, transform);
            }
        }
    } else {
        let bytes = fs::read(path)?;
        decoder.push(CqueryResult::decode_from_slice(&bytes)?, transform);
    }
    Ok(decoder.finish(transform))
}

/// Separator between a label and the checksum of the configuration a target was analyzed in.
///
/// A cquery graph is a graph of *configured* targets: one label can be analyzed in several
/// configurations (a transition, an exec dependency, a `select()` that resolves differently),
/// and those instances have different dependencies. Bazel identifies each dependency edge by
/// `(label, configuration checksum)` in `configured_rule_input`, and that is the identity
/// the rule-input encoding folds into `label|checksum`. Configured targets are named the same
/// way, so an edge resolves to the instance it points at rather than to whichever instance of
/// the label happened to come first. Collapsing by label loses edges and, when an instance
/// depends on the same label in another configuration, reports a cycle the configured graph
/// does not have.
pub const CONFIGURED_SEPARATOR: char = '|';

/// Bazel reports the null configuration (source files, package groups) with this checksum.
const NULL_CONFIGURATION_CHECKSUM: &str = "null";

/// Decodes `CqueryResult` messages into targets named by their configured identity.
///
/// Each result carries its configuration inline (the deprecated `configuration` field, which
/// Bazel still populates) and by id into `CqueryResult.configurations`. A streamed result's
/// id table only arrives after the results that use it, so a result whose inline checksum is
/// missing waits until the stream ends to be named.
///
/// Resolving a checksum is the only step that depends on earlier messages. Named targets queue
/// in `ready` and are lowered, configured and handed to `transform` a batch at a time in
/// parallel, in the order they were named.
#[derive(Default)]
struct CqueryDecoder {
    targets: Vec<Target>,
    configurations: HashMap<u32, String>,
    pending: Vec<(Target, u32)>,
    ready: Vec<(Target, Option<String>)>,
    lowered: Vec<Option<Target>>,
}

impl CqueryDecoder {
    fn push(&mut self, result: CqueryResult, transform: &mut impl FnMut(&mut [Target])) {
        for configuration in result.configurations {
            if let Some(checksum) = non_null_checksum(&configuration.checksum) {
                self.configurations
                    .insert(configuration.id, checksum.to_owned());
            }
        }
        for configured in result.results {
            let ConfiguredTarget {
                target,
                configuration,
                configuration_id,
                ..
            } = configured;
            let Some(target) = target.into_option() else {
                continue;
            };
            let inline = configuration
                .as_option()
                .and_then(|configuration| non_null_checksum(&configuration.checksum))
                .map(str::to_owned);
            let checksum = inline.or_else(|| self.configurations.get(&configuration_id).cloned());
            if checksum.is_none() && configuration_id != 0 {
                self.pending.push((target, configuration_id));
                continue;
            }
            self.ready.push((target, checksum));
            if self.ready.len() >= DECODE_BATCH_MESSAGES {
                self.flush(transform);
            }
        }
    }

    fn flush(&mut self, transform: &mut impl FnMut(&mut [Target])) {
        if self.ready.is_empty() {
            return;
        }
        self.ready
            .par_drain(..)
            .map(|(target, checksum)| {
                let mut target = lower_target(target)?;
                if let Some(checksum) = checksum {
                    configure_target(&mut target, &checksum);
                }
                Some(target)
            })
            .collect_into_vec(&mut self.lowered);
        let start = self.targets.len();
        self.targets.extend(self.lowered.drain(..).flatten());
        if self.targets.len() > start {
            transform(&mut self.targets[start..]);
        }
    }

    fn finish(mut self, transform: &mut impl FnMut(&mut [Target])) -> Vec<Target> {
        self.flush(transform);
        let pending = std::mem::take(&mut self.pending);
        for (target, configuration_id) in pending {
            let checksum = self.configurations.get(&configuration_id).cloned();
            self.ready.push((target, checksum));
            if self.ready.len() >= DECODE_BATCH_MESSAGES {
                self.flush(transform);
            }
        }
        self.flush(transform);
        self.targets
    }
}

fn non_null_checksum(checksum: &str) -> Option<&str> {
    (!checksum.is_empty() && checksum != NULL_CONFIGURATION_CHECKSUM).then_some(checksum)
}

/// Names a rule or generated file by its configured identity, `label|checksum`.
///
/// Source files are never configured (Bazel reports them in the null configuration), so their
/// labels stay bare and keep matching the bare labels in `configured_rule_input`. A generated
/// file shares its generating rule's configuration, so that reference is named the same way.
fn configure_target(target: &mut Target, checksum: &str) {
    match target.r#type {
        target::Discriminator::Rule => {
            if let Some(rule) = target.rule.as_option_mut() {
                rule.name = configured_key(&rule.name, checksum);
            }
        }
        target::Discriminator::GeneratedFile => {
            if let Some(file) = target.generated_file.as_option_mut() {
                file.name = configured_key(&file.name, checksum);
                file.generating_rule = configured_key(&file.generating_rule, checksum);
            }
        }
        _ => {}
    }
}

pub fn configured_key(label: &str, checksum: &str) -> String {
    format!("{label}{CONFIGURED_SEPARATOR}{checksum}")
}

/// Splits a configured identity into its label and configuration checksum.
///
/// Bazel allows `|` in target names, so the suffix only counts as a checksum when it looks
/// like one (non-empty, hexadecimal); a bare label is returned unchanged.
pub fn split_configured(key: &str) -> (&str, Option<&str>) {
    match key.rsplit_once(CONFIGURED_SEPARATOR) {
        Some((label, checksum))
            if !checksum.is_empty() && checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            (label, Some(checksum))
        }
        _ => (key, None),
    }
}

/// The label of a configured identity, or the input unchanged when it is a bare label.
pub fn target_label(key: &str) -> &str {
    split_configured(key).0
}

/// One spelling of a main-repository label, for comparing labels Bazel printed in
/// different forms: `@@//pkg:name` (Bzlmod), `@//pkg:name` (WORKSPACE mode) and the
/// apparent `//pkg:name` that `repr()` gives a main-repository alias all become
/// `//pkg:name`. Other labels are returned unchanged.
fn main_repo_label_key(label: &str) -> &str {
    label
        .strip_prefix("@@")
        .or_else(|| label.strip_prefix('@'))
        .filter(|rest| rest.starts_with("//"))
        .unwrap_or(label)
}

pub fn target_name(target: &Target) -> Option<&str> {
    match target.r#type {
        target::Discriminator::Rule => target.rule.as_option().map(|rule| rule.name.as_str()),
        target::Discriminator::SourceFile => target
            .source_file
            .as_option()
            .map(|source| source.name.as_str()),
        target::Discriminator::GeneratedFile => target
            .generated_file
            .as_option()
            .map(|generated| generated.name.as_str()),
        target::Discriminator::PackageGroup => target
            .package_group
            .as_option()
            .map(|group| group.name.as_str()),
        target::Discriminator::EnvironmentGroup => target
            .environment_group
            .as_option()
            .map(|group| group.name.as_str()),
    }
}

fn add_legacy_toolchain_inputs(target: &mut Target) {
    if let Some(rule) = target
        .rule
        .as_option_mut()
        .filter(|r| r.rule_class == "toolchain")
    {
        // Bazel's native toolchain rule points at its implementation with a NODEP_LABEL.
        // Query prints the label as a nodep string and omits it from rule_input.
        if let Some(implementation) = rule
            .attribute
            .iter()
            .find(|a| a.name == "toolchain" && a.nodep == Some(true))
        {
            rule.rule_input
                .extend(implementation.string_value.iter().cloned());
            if let Some(select) = implementation.selector_list.as_option() {
                rule.rule_input
                    .extend(select.elements.iter().flat_map(|element| {
                        element
                            .entries
                            .iter()
                            .filter_map(|entry| entry.string_value.clone())
                    }));
            }
        }
    }
}

fn lower_target(target: Target) -> Option<Target> {
    lower_target_with_class_keys(target, false)
}

fn lower_target_with_class_keys(mut target: Target, keep_class_keys: bool) -> Option<Target> {
    match target.r#type {
        target::Discriminator::Rule
        | target::Discriminator::SourceFile
        | target::Discriminator::GeneratedFile => {
            compact_target(&mut target, keep_class_keys);
            Some(target)
        }
        target::Discriminator::PackageGroup => {
            let group = target.package_group.take()?;
            target.r#type = target::Discriminator::Rule;
            target.rule = buffa::MessageField::some(package_group_rule(&group));
            compact_target(&mut target, false);
            Some(target)
        }
        target::Discriminator::EnvironmentGroup => {
            eprintln!("[Warn] Unsupported target type in the build graph: ENVIRONMENT_GROUP");
            None
        }
    }
}

fn retained_class_key(key: &str) -> bool {
    matches!(
        key,
        "alias" | "filegroup" | "package_group" | "toolchain" | "toolchain_type"
    ) || is_condition_class(key)
}

struct StockRuleClass {
    representative: usize,
    members: Vec<usize>,
}

#[derive(Default)]
struct StockWalk {
    inputs: BTreeMap<String, BTreeSet<String>>,
    returned: BTreeSet<String>,
    unrecognized: BTreeSet<String>,
    complete: bool,
}

impl StockWalk {
    fn has_input(&self, owner: &str, input: &str) -> Option<bool> {
        if self
            .inputs
            .get(owner)
            .is_some_and(|inputs| inputs.contains(input))
        {
            return Some(true);
        }
        (self.complete && self.returned.contains(owner) && !self.unrecognized.contains(owner))
            .then_some(false)
    }
}

#[derive(Default)]
struct StockFlat {
    inputs: BTreeMap<String, BTreeSet<String>>,
    complete: bool,
}

impl StockFlat {
    fn inputs(&self, owner: &str) -> Option<&BTreeSet<String>> {
        if self.complete {
            self.inputs.get(owner)
        } else {
            None
        }
    }
}

fn queue_stock_inputs(
    walk: &StockWalk,
    samples: &BTreeMap<String, Vec<usize>>,
    targets: &[Target],
    mapping: &HashMap<String, String>,
    inputs: &mut BTreeMap<usize, BTreeSet<String>>,
) {
    for (owner, values) in &walk.inputs {
        if let Some(indices) = samples.get(owner) {
            for &index in indices {
                let rule = targets[index].rule.as_option().expect("indexed rule");
                let ordinary = rule
                    .rule_input
                    .iter()
                    .map(|input| canonical_query_label(input, mapping).into_owned())
                    .collect::<HashSet<_>>();
                inputs.entry(index).or_default().extend(
                    values
                        .iter()
                        .filter(|value| !ordinary.contains(*value))
                        .cloned(),
                );
            }
        }
    }
}

fn queue_stock_uncertainty(
    uncertain: &mut BTreeMap<usize, BTreeSet<String>>,
    group: usize,
    input: &str,
) {
    if let Some((repository, _)) = input
        .strip_prefix("@@")
        .and_then(|label| label.split_once("//"))
    {
        if !repository.is_empty() {
            uncertain
                .entry(group)
                .or_default()
                .insert(repository.to_owned());
        }
    }
}

fn add_stock_inputs(
    targets: &mut [Target],
    members: &[usize],
    inputs: &BTreeSet<String>,
    mapping: &HashMap<String, String>,
    observed: &HashMap<String, usize>,
) {
    let inputs = inputs
        .iter()
        .map(|input| {
            let spelling = observed
                .get(input)
                .and_then(|&index| target_name(&targets[index]))
                .unwrap_or(input)
                .to_owned();
            (input, spelling)
        })
        .collect::<Vec<_>>();
    for &index in members {
        let rule = targets[index].rule.as_option_mut().expect("indexed rule");
        let mut present = rule
            .rule_input
            .iter()
            .map(|input| canonical_query_label(input, mapping).into_owned())
            .collect::<HashSet<_>>();
        for (input, spelling) in &inputs {
            if present.insert((*input).clone()) {
                rule.rule_input.push(spelling.clone());
            }
        }
    }
}

/// Bazel's key identifies one RuleClass and its default toolchain requirements.
/// Stop carrying full keys as soon as the primary rows have stable indices.
fn take_stock_rule_classes(
    targets: &mut [Target],
    mapping: &HashMap<String, String>,
) -> BTreeMap<String, StockRuleClass> {
    let mut members_by_key = BTreeMap::<String, Vec<usize>>::new();
    for (index, target) in targets.iter_mut().enumerate() {
        let Some(rule) = target.rule.as_option_mut() else {
            continue;
        };
        let Some(key) = rule.rule_class_key.take() else {
            continue;
        };
        if retained_class_key(&key) {
            rule.rule_class_key = Some(key.clone());
        }
        // Bzlmod inventory rows and normalized package groups have synthetic Rule identities.
        if !key.is_empty() && !rule.name.starts_with("//external:") && key != "package_group" {
            members_by_key.entry(key).or_default().push(index);
        }
    }
    members_by_key
        .into_iter()
        .filter_map(|(key, members)| {
            let representative = members
                .iter()
                .filter_map(|&index| {
                    let name = target_name(&targets[index])?;
                    let canonical = canonical_query_label(name, mapping);
                    // DOT writes target labels without quoting embedded double quotes.
                    (!canonical.contains('"')).then_some((canonical, name, index))
                })
                .min()?
                .2;
            Some((
                key,
                StockRuleClass {
                    representative,
                    members,
                },
            ))
        })
        .collect()
}

fn compact_target(target: &mut Target, keep_class_keys: bool) {
    target.__buffa_unknown_fields.clear();
    match target.r#type {
        target::Discriminator::Rule => {
            let Some(rule) = target.rule.as_option_mut() else {
                return;
            };
            rule.location = None;
            rule.rule_output.clear();
            rule.default_setting.clear();
            rule.DEPRECATED_public_by_default = None;
            rule.DEPRECATED_is_skylark = None;
            rule.definition_stack.clear();
            if !keep_class_keys
                && !rule
                    .rule_class_key
                    .as_deref()
                    .is_some_and(retained_class_key)
            {
                rule.rule_class_key = None;
            }
            rule.__buffa_unknown_fields.clear();
        }
        target::Discriminator::SourceFile => {
            let Some(source) = target.source_file.as_option_mut() else {
                return;
            };
            source.location = None;
            source.package_group.clear();
            source.visibility_label.clear();
            source.feature.clear();
            source.license = buffa::MessageField::none();
            source.package_contains_errors = None;
            source.__buffa_unknown_fields.clear();
        }
        target::Discriminator::GeneratedFile => {
            let Some(generated) = target.generated_file.as_option_mut() else {
                return;
            };
            generated.location = None;
            generated.__buffa_unknown_fields.clear();
        }
        _ => {}
    }
}

fn package_group_rule(group: &PackageGroup) -> Rule {
    let packages = Attribute {
        name: "packages".to_owned(),
        r#type: crate::proto::blaze_query::attribute::Discriminator::StringList,
        string_list_value: group.contained_package.clone(),
        ..Default::default()
    };
    let mut rule = Rule {
        name: group.name.clone(),
        rule_class: "package_group".to_owned(),
        // The wire target is a PackageGroup, not a same-named Starlark rule.
        rule_class_key: Some("package_group".to_owned()),
        ..Default::default()
    };
    rule.attribute.push(packages);
    rule.rule_input = group.included_package_group.clone();
    rule
}

struct RepositoryFiles {
    tree_hash: Option<String>,
    inputs_hash: Option<String>,
}

fn prepare_repository(
    repository: &mut Repository,
    workspace: &RepositoryWorkspace<'_>,
) -> RepositoryFiles {
    // Resolve physical inputs using the original attribute values.
    let files = RepositoryFiles {
        tree_hash: local_repository_content_hash(repository, workspace.path),
        inputs_hash: repository_local_inputs_hash(repository, workspace.path),
    };
    normalize_workspace_attributes(&mut repository.attribute, &workspace.roots);
    files
}

fn repository_rule(
    repository: Repository,
    files: RepositoryFiles,
    owner_definition_hash: Option<&str>,
) -> Rule {
    let mut rule = Rule {
        rule_class: repository
            .repo_rule_name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "bzlmod_repo".to_owned()),
        attribute: repository.attribute,
        ..Default::default()
    };
    let mut push_attribute = |name: &str, value: String| {
        let mut attribute = Attribute::default();
        attribute.name = name.to_owned();
        attribute.r#type = crate::proto::blaze_query::attribute::Discriminator::String;
        attribute.string_value = Some(value);
        rule.attribute.push(attribute);
    };
    if let Some(content_hash) = files.tree_hash {
        push_attribute("_bazel_diff_content_hash", content_hash);
    }
    if let Some(inputs_hash) = files.inputs_hash {
        push_attribute("_bazel_diff_local_inputs_hash", inputs_hash);
    }
    if let Some(owner_hash) = owner_definition_hash {
        push_attribute("_bazel_diff_module_hash", owner_hash.to_owned());
    }
    rule
}

fn repository_target(mut rule: Rule, apparent: &str, dependencies: &BTreeSet<String>) -> Target {
    rule.name = format!("//external:{apparent}");
    rule.rule_input = dependencies
        .iter()
        .filter(|dependency| dependency.as_str() != apparent)
        .map(|dependency| format!("//external:{dependency}"))
        .collect();
    let mut target = Target::default();
    target.r#type = target::Discriminator::Rule;
    target.rule = buffa::MessageField::some(rule);
    target
}

/// Every main-repository label a repository rule's attributes point at: `patches`, `build_file`,
/// a `requirements_lock`, and so on. Attributes only name these files; a repository fetched with
/// a changed patch is a different repository, so their contents must reach its hash.
fn repository_local_input_labels(repository: &Repository) -> BTreeSet<&str> {
    attribute_main_repo_labels(&repository.attribute).collect()
}

/// Every main-repository label among the attributes' values: the files and directories a
/// repository rule reads from the workspace (`build_file`, `patches`, a requirements file).
pub(crate) fn attribute_main_repo_labels(attributes: &[Attribute]) -> impl Iterator<Item = &str> {
    attributes.iter().flat_map(|attr| {
        attribute_label_values(attr)
            .chain(
                attr.string_dict_value
                    .iter()
                    .map(|entry| entry.value.as_str()),
            )
            .chain(
                attr.label_dict_unary_value
                    .iter()
                    .map(|entry| entry.key.as_str()),
            )
            .filter(|value| crate::hash::main_repo_path(value).is_some())
    })
}

/// The slots that can name targets after the caller checks the attribute discriminator.
/// LABEL_DICT_UNARY is string -> label and LABEL_KEYED_STRING_DICT is label -> string.
fn attribute_label_values(attribute: &Attribute) -> impl Iterator<Item = &str> {
    attribute
        .string_value
        .iter()
        .chain(&attribute.string_list_value)
        .chain(
            attribute
                .label_dict_unary_value
                .iter()
                .map(|entry| &entry.value),
        )
        .chain(
            attribute
                .label_keyed_string_dict_value
                .iter()
                .map(|entry| &entry.key),
        )
        .chain(
            attribute
                .label_list_dict_value
                .iter()
                .flat_map(|entry| &entry.value),
        )
        // Bazel's AttributeFormatter emits LABEL_LIST_DICT in the same field as
        // STRING_LIST_DICT. Only the former is a typed repository input.
        .chain(
            attribute
                .string_list_dict_value
                .iter()
                .flat_map(|entry| &entry.value),
        )
        .map(String::as_str)
}

/// Digest of a repository's own definition: its rule, its attributes, and the local tree and
/// main-repository files behind them. Like the target hasher, it leaves out URLs whose content an
/// integrity pins: `url`/`urls` under `sha256`/`integrity`, and the URLs
/// `without_integrity_pinned_urls` drops.
fn repository_definition_hash(repository: &Repository, files: &RepositoryFiles) -> String {
    let pinned = repository.attribute.iter().any(|attribute| {
        matches!(attribute.name.as_str(), "sha256" | "integrity")
            && attribute
                .string_value
                .as_deref()
                .is_some_and(|value| !value.is_empty())
    });
    let mut hasher = Sha256::new();
    hasher.update(repository.repo_rule_name.as_deref().unwrap_or_default());
    hasher.update([0]);
    let mut encoded = Vec::new();
    for attribute in &repository.attribute {
        if pinned && matches!(attribute.name.as_str(), "url" | "urls") {
            continue;
        }
        encoded.clear();
        match crate::hash::without_integrity_pinned_urls(attribute, &repository.attribute) {
            Some(stripped) => stripped.encode_length_delimited(&mut encoded),
            None => attribute.encode_length_delimited(&mut encoded),
        }
        hasher.update(&encoded);
    }
    hasher.update([0]);
    if let Some(content_hash) = &files.tree_hash {
        hasher.update(content_hash);
    }
    hasher.update([0]);
    if let Some(inputs_hash) = &files.inputs_hash {
        hasher.update(inputs_hash);
    }
    hex::encode(hasher.finalize())
}

/// Hashes the contents of the main-repository files named by `repository`'s attributes, in label
/// order. `None` when the attributes name no such file that exists in the workspace.
fn repository_local_inputs_hash(repository: &Repository, workspace: &Path) -> Option<String> {
    let mut hasher = Sha256::new();
    let mut hashed_any = false;
    for label in repository_local_input_labels(repository) {
        let Some(path) = crate::hash::main_repo_path(label) else {
            continue;
        };
        let absolute = workspace.join(path);
        let mut content = Sha256::new();
        if absolute.is_file() {
            content.update(fs::read(&absolute).ok()?);
        } else if absolute.is_dir() {
            crate::hash::hash_directory_into(&mut content, &absolute).ok()?;
        } else {
            continue;
        }
        hasher.update(label.as_bytes());
        hasher.update([0]);
        hasher.update(content.finalize());
        hasher.update([0]);
        hashed_any = true;
    }
    hashed_any.then(|| hex::encode(hasher.finalize()))
}

fn local_repository_content_hash(repository: &Repository, workspace: &Path) -> Option<String> {
    if repository.repo_rule_name.as_deref() != Some("local_repository") {
        return None;
    }
    let path = repository
        .attribute
        .iter()
        .find(|attribute| attribute.name == "path")
        .and_then(|attribute| attribute.string_value.as_deref())?;
    let path = PathBuf::from(path);
    let root = if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    };
    if !root.is_dir() {
        return None;
    }
    let mut files = walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.file_name() != "MODULE.bazel.lock")
        .collect::<Vec<_>>();
    files.sort_by_key(|entry| entry.path().to_owned());
    let mut hasher = Sha256::new();
    for entry in files {
        let relative = entry.path().strip_prefix(&root).ok()?;
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(fs::read(entry.path()).ok()?);
        hasher.update([0]);
    }
    Some(hex::encode(hasher.finalize()))
}

struct RepositoryWorkspace<'a> {
    path: &'a Path,
    roots: Vec<String>,
}

impl<'a> RepositoryWorkspace<'a> {
    fn new(path: &'a Path) -> Self {
        Self {
            path,
            roots: workspace_roots(path),
        }
    }
}

/// The workspace root as given and as resolved, the two spellings an absolute path in a
/// repository attribute can start with.
fn workspace_roots(workspace: &Path) -> Vec<String> {
    let mut roots = vec![workspace.to_string_lossy().trim_end_matches('/').to_owned()];
    if let Ok(resolved) = fs::canonicalize(workspace) {
        let resolved = resolved.to_string_lossy().trim_end_matches('/').to_owned();
        if !roots.contains(&resolved) {
            roots.push(resolved);
        }
    }
    roots.retain(|root| !root.is_empty());
    roots
}

/// Rewrites a path inside the workspace, bare or as a `file://` URL, to start with
/// `%workspace%`. Anything else keeps its spelling: a path that merely contains the workspace's
/// (`/elsewhere/<workspace>/data`), and one that starts with it but leaves it, through `..` or a
/// symlink. Rewriting those would let two different paths outside two checkouts hash the same.
fn workspace_relative<'a>(value: &'a str, roots: &[String]) -> Cow<'a, str> {
    let (scheme, path) = value
        .strip_prefix("file://")
        .map_or(("", value), |path| ("file://", path));
    for root in roots {
        let rest = path
            .strip_prefix(root.as_str())
            .filter(|rest| rest.is_empty() || rest.starts_with('/'));
        if let Some(rest) = rest {
            if !stays_inside(root, rest) {
                break;
            }
            return Cow::Owned(format!("{scheme}%workspace%{rest}"));
        }
    }
    Cow::Borrowed(value)
}

/// Whether `root` followed by `rest` (empty or starting with `/`) names something inside `root`:
/// its `..` components never climb above `root`, and its deepest existing ancestor, with symlinks
/// resolved, is still under `root`. A path that does not exist yet is judged by its spelling.
fn stays_inside(root: &str, rest: &str) -> bool {
    let mut depth = 0usize;
    let mut normalized = PathBuf::from(root);
    for component in rest
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
    {
        if component == ".." {
            let Some(up) = depth.checked_sub(1) else {
                return false;
            };
            depth = up;
            normalized.pop();
        } else {
            depth += 1;
            normalized.push(component);
        }
    }
    let Ok(root) = fs::canonicalize(root) else {
        return true;
    };
    let existing = normalized.ancestors().find(|ancestor| ancestor.exists());
    existing.is_none_or(|ancestor| {
        fs::canonicalize(ancestor).is_ok_and(|resolved| resolved.starts_with(&root))
    })
}

/// Repository attributes with the workspace root replaced by `%workspace%`. Repository rules
/// that build from a directory in the workspace, such as Gazelle's `go_repository` with
/// `local_path` or a `rules_rs` local crate, get that directory as an absolute path, so the same
/// repository would otherwise hash differently in every checkout.
fn normalize_workspace_attributes(attributes: &mut [Attribute], roots: &[String]) {
    let rewrite = |value: &mut String| {
        if let Cow::Owned(relative) = workspace_relative(value, roots) {
            *value = relative;
        }
    };
    for attribute in attributes {
        attribute.string_value.iter_mut().for_each(rewrite);
        attribute.string_list_value.iter_mut().for_each(rewrite);
        for entry in &mut attribute.string_dict_value {
            rewrite(&mut entry.key);
            rewrite(&mut entry.value);
        }
        for entry in &mut attribute.string_list_dict_value {
            rewrite(&mut entry.key);
            entry.value.iter_mut().for_each(rewrite);
        }
    }
}

fn parse_module_dependency_edges(json: &str) -> BTreeMap<String, BTreeSet<String>> {
    fn walk(value: &serde_json::Value, edges: &mut BTreeMap<String, BTreeSet<String>>) {
        let Some(object) = value.as_object() else {
            return;
        };
        let Some(name) = object.get("name").and_then(serde_json::Value::as_str) else {
            return;
        };
        let Some(dependencies) = object
            .get("dependencies")
            .and_then(serde_json::Value::as_array)
        else {
            return;
        };
        for dependency in dependencies {
            if let Some(dependency_name) =
                dependency.get("name").and_then(serde_json::Value::as_str)
            {
                edges
                    .entry(name.to_owned())
                    .or_default()
                    .insert(dependency_name.to_owned());
            }
            walk(dependency, edges);
        }
    }
    let start = json.find('{').unwrap_or(json.len());
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&json[start..]) else {
        return BTreeMap::new();
    };
    let mut edges = BTreeMap::new();
    walk(&value, &mut edges);
    break_module_cycles(edges)
}

/// Every module in the resolved graph whose repository is not in the root's repo mapping, as
/// module key (`name@version`, which `bazel mod show_repo` accepts) -> canonical repository
/// name (which `bazel mod dump_repo_mapping` wants). Bazel names a module's repository
/// `name+`, or `name+version` when `multiple_version_override` keeps several versions of it.
fn hidden_module_repo_names(
    json: &str,
    canonical_to_apparent: &BTreeMap<String, Vec<String>>,
) -> BTreeMap<String, String> {
    fn walk(value: &serde_json::Value, keys: &mut BTreeMap<String, String>) {
        let Some(object) = value.as_object() else {
            return;
        };
        if let (Some(key), Some(name)) = (
            object.get("key").and_then(serde_json::Value::as_str),
            object.get("name").and_then(serde_json::Value::as_str),
        ) {
            if key != "<root>" {
                keys.insert(key.to_owned(), name.to_owned());
            }
        }
        for dependency in object
            .get("dependencies")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            walk(dependency, keys);
        }
    }
    let start = json.find('{').unwrap_or(json.len());
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&json[start..]) else {
        return BTreeMap::new();
    };
    let mut keys = BTreeMap::new();
    walk(&value, &mut keys);
    module_repo_names(&keys, canonical_to_apparent, false)
}

/// Decode the fields JsonOutputFormatter uses for repository enumeration. Repeated and cycle
/// references may be unexpanded, but every module must expand somewhere to reveal its children.
fn isolated_module_repo_names(
    json: &str,
    canonical_to_apparent: &BTreeMap<String, Vec<String>>,
) -> Result<BTreeMap<String, String>> {
    #[derive(serde::Deserialize)]
    struct Module {
        key: String,
        name: String,
        #[serde(default)]
        dependencies: Option<Vec<Module>>,
        #[serde(default, rename = "indirectDependencies")]
        indirect_dependencies: Vec<Module>,
        #[serde(default)]
        cycles: Vec<Module>,
        #[serde(default)]
        unexpanded: bool,
    }

    fn walk(
        module: &Module,
        keys: &mut BTreeMap<String, String>,
        expanded: &mut BTreeSet<String>,
        root: bool,
    ) -> Result<()> {
        let Module {
            key,
            name,
            dependencies,
            indirect_dependencies,
            cycles,
            unexpanded,
        } = module;
        if root {
            if key != "<root>" {
                bail!("module graph root key is {key}, expected <root>");
            }
            if *unexpanded {
                bail!("module graph root is unexpanded");
            }
        }
        if dependencies.is_none() && !unexpanded {
            bail!("module graph entry {key} has no dependencies array");
        }
        if key != "<root>" {
            if name.is_empty()
                || key
                    .rsplit_once('@')
                    .is_none_or(|(module, version)| module != name || version.is_empty())
            {
                bail!("module graph key {key} does not identify {name}@version");
            }
            keys.insert(key.clone(), name.clone());
            if !unexpanded {
                expanded.insert(key.clone());
            }
        }
        for dependency in dependencies
            .iter()
            .flatten()
            .chain(indirect_dependencies)
            .chain(cycles)
        {
            walk(dependency, keys, expanded, false)?;
        }
        Ok(())
    }

    let start = json.find('{').unwrap_or(json.len());
    let graph: Module =
        serde_json::from_str(&json[start..]).context("invalid module graph JSON")?;
    let mut keys = BTreeMap::new();
    let mut expanded = BTreeSet::new();
    walk(&graph, &mut keys, &mut expanded, true)?;
    for key in keys.keys() {
        if !expanded.contains(key) {
            bail!("module graph entry {key} is only an unexpanded reference");
        }
    }
    Ok(module_repo_names(&keys, canonical_to_apparent, true))
}

/// Required inventories match full canonical names: importing one version does not expose another
/// version's mapping. The tolerant path retains its historical module-name filtering.
fn module_repo_names(
    keys: &BTreeMap<String, String>,
    canonical_to_apparent: &BTreeMap<String, Vec<String>>,
    exact_visibility: bool,
) -> BTreeMap<String, String> {
    let visible_modules = canonical_to_apparent
        .keys()
        .filter(|canonical| canonical.matches('+').count() <= 1)
        .filter_map(|canonical| canonical.split('+').next())
        .collect::<BTreeSet<_>>();
    let mut versions_by_name = BTreeMap::<&str, usize>::new();
    for name in keys.values() {
        *versions_by_name.entry(name.as_str()).or_default() += 1;
    }
    keys.iter()
        .filter_map(|(key, name)| {
            if !exact_visibility && visible_modules.contains(name.as_str()) {
                return None;
            }
            let version = key.rsplit_once('@').map_or("", |(_, version)| version);
            let canonical = if WELL_KNOWN_MODULES.contains(&name.as_str()) {
                name.clone()
            } else if versions_by_name.get(name.as_str()).copied().unwrap_or(0) > 1 {
                format!("{name}+{version}")
            } else {
                format!("{name}+")
            };
            (!exact_visibility || !canonical_to_apparent.contains_key(&canonical))
                .then(|| (key.clone(), canonical))
        })
        .collect()
}

/// Modules Bazel ships with, whose repositories keep their bare name rather than `name+`.
const WELL_KNOWN_MODULES: [&str; 3] = ["bazel_tools", "local_config_platform", "platforms"];

fn break_module_cycles(
    edges: BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    fn visit(
        node: &str,
        edges: &BTreeMap<String, BTreeSet<String>>,
        visited: &mut BTreeSet<String>,
        path: &mut BTreeSet<String>,
        result: &mut BTreeMap<String, BTreeSet<String>>,
    ) {
        if visited.contains(node) {
            return;
        }
        path.insert(node.to_owned());
        let mut kept = BTreeSet::new();
        for dependency in edges.get(node).into_iter().flatten() {
            if path.contains(dependency) {
                continue;
            }
            kept.insert(dependency.clone());
            visit(dependency, edges, visited, path, result);
        }
        result.insert(node.to_owned(), kept);
        path.remove(node);
        visited.insert(node.to_owned());
    }
    let mut result = BTreeMap::new();
    let mut visited = BTreeSet::new();
    for node in edges.keys() {
        visit(
            node,
            &edges,
            &mut visited,
            &mut BTreeSet::new(),
            &mut result,
        );
    }
    result
}

pub fn encode_configured_input(input: &ConfiguredRuleInput) -> String {
    match input.configuration_checksum.as_deref() {
        Some(checksum) if !checksum.is_empty() => {
            configured_key(input.label.as_deref().unwrap_or_default(), checksum)
        }
        _ => input.label.clone().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::analysis::{Configuration, ConfiguredTarget, CqueryResult};
    use crate::proto::blaze_query::{
        attribute, EnvironmentGroup, GeneratedFile, LabelDictUnaryEntry, SourceFile,
    };
    fn rule_target(name: &str) -> Target {
        let mut target = Target::default();
        target.r#type = target::Discriminator::Rule;
        target.rule = buffa::MessageField::some(Rule {
            name: name.to_owned(),
            rule_class: "sh_library".to_owned(),
            ..Default::default()
        });
        target
    }

    fn write_delimited(path: &Path, messages: &[impl Message]) {
        let mut bytes = Vec::new();
        for message in messages {
            message.encode_length_delimited(&mut bytes);
        }
        fs::write(path, bytes).unwrap();
    }

    fn prepared_definition_hash(
        repository: &Repository,
        workspace: &RepositoryWorkspace<'_>,
    ) -> String {
        let mut repository = repository.clone();
        let files = prepare_repository(&mut repository, workspace);
        repository_definition_hash(&repository, &files)
    }

    fn prepared_target(
        repository: &Repository,
        apparent: &str,
        dependencies: &BTreeSet<String>,
        owner: Option<&str>,
        workspace: &RepositoryWorkspace<'_>,
    ) -> Target {
        let mut repository = repository.clone();
        let files = prepare_repository(&mut repository, workspace);
        repository_target(
            repository_rule(repository, files, owner),
            apparent,
            dependencies,
        )
    }

    #[test]
    fn static_toolchain_scope_accepts_worker_serialization_and_strictness() {
        let mut options = probe_options(Path::new("."), PathBuf::from("unused"));
        options.command_options = [
            "--proto:output_rule_attrs=tags",
            "--proto:include_synthetic_attribute_hash",
            "--curses=no",
            "--nokeep_going",
        ]
        .map(str::to_owned)
        .to_vec();
        assert!(options.static_toolchain_scope_matches());
        options
            .command_options
            .push("--override_module=provider=/workspace/provider".into());
        assert!(!options.static_toolchain_scope_matches());
    }

    #[test]
    fn module_toolchain_registrations_preserve_order_and_reject_invalid_fields() {
        let parse = |labels: &str| {
            let graph =
                serde_json::from_str(&format!(r#"{{"moduleToolchainRegistrations":{labels}}}"#))
                    .unwrap();
            ModuleToolchainRegistrations::from_graph(&graph)
        };
        let first = parse(r#"["//:second","//:first","@@provider+//:explicit"]"#).unwrap();
        assert_eq!(
            first.labels,
            ["//:second", "//:first", "@@provider+//:explicit"]
        );
        assert_ne!(
            first,
            parse(r#"["//:first","//:second","@@provider+//:explicit"]"#).unwrap()
        );
        assert!(parse("[]").unwrap().labels.is_empty());
        assert!(ModuleToolchainRegistrations::from_graph(&serde_json::json!({})).is_none());
        for invalid in [
            r#"["@provider//:apparent"]"#,
            r#"["//:first","//:first"]"#,
            "[1]",
            "null",
        ] {
            assert!(parse(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn static_module_registrations_preserve_known_paths_and_unresolved_choices() {
        let decl = |ty: &str| StaticToolchainDeclaration {
            ty: ty.into(),
            implementations: BTreeSet::from(["//impl:tool".into()]),
            ordinary_inputs: BTreeSet::new(),
        };
        let mut graph = StaticToolchains {
            registration_order: ["//:second", "//:mixed", "//:first", "//:missing"]
                .map(str::to_owned)
                .to_vec(),
            declarations: BTreeMap::from([
                ("//:second".into(), decl("//:type")),
                ("//:first".into(), decl("//:type_alias")),
                // Exposed on the ordinary graph but never registered with MODULE.
                ("//:available_only".into(), decl("//:type")),
                ("//:same_key".into(), decl("//:absent_type")),
            ]),
            aliases: BTreeMap::from([
                (
                    "//:mixed".into(),
                    vec!["//:first".into(), "//:cycle".into()],
                ),
                ("//:cycle".into(), vec!["//:mixed".into()]),
                (
                    "//:type_alias".into(),
                    vec!["//:middle_type".into(), "//:other_type".into()],
                ),
                ("//:middle_type".into(), vec!["//:type".into()]),
                (
                    "//:required_spelling".into(),
                    vec!["//:type".into(), "//:reader_only_leaf".into()],
                ),
            ]),
            native_types: BTreeSet::from([
                "//:type".into(),
                "//:other_type".into(),
                "//:reader_only_leaf".into(),
            ]),
            ..Default::default()
        };
        graph.registration_order.push("//:same_key".into());
        // A partial query still returned the structure of first. Its positive
        // binding can be used, but a parent literal cannot call that complete.
        graph.unresolved.insert("//:first".into());
        graph
            .aliases
            .insert("//:partial".into(), vec!["//:first".into()]);
        graph.registration_order.push("//:partial".into());
        graph.registration_order.push("//:diamond".into());
        graph.aliases.insert(
            "//:diamond".into(),
            vec!["//:left".into(), "//:right".into()],
        );
        for branch in ["//:left", "//:right"] {
            graph.aliases.insert(
                branch.into(),
                vec!["//:first".into(), format!("{branch}_missing")],
            );
        }
        graph.index_types(&BTreeSet::from([
            "//:type".into(),
            "//:absent_type".into(),
            "//:required_spelling".into(),
        ]));
        assert_eq!(
            graph.type_paths["//:required_spelling"],
            BTreeSet::from(
                [
                    "//:required_spelling",
                    "//:type_alias",
                    "//:middle_type",
                    "//:type"
                ]
                .map(str::to_owned)
            )
        );
        assert!(graph.type_paths["//:absent_type"].is_empty());
        assert_eq!(
            graph.by_type["//:type"],
            [
                "//:second",
                "//:mixed",
                "//:first",
                "//:partial",
                "//:diamond"
            ]
        );
        assert_eq!(graph.by_type["//:absent_type"], ["//:same_key"]);
        for missing in ["//:missing", "//:mixed", "//:absent_type", "//:partial"] {
            assert!(graph.unresolved.contains(missing), "{missing}");
        }
        assert!(!graph.unresolved.contains("//:second"));
        let mixed = &graph.registration_paths["//:mixed"];
        assert_eq!(mixed.aliases, BTreeSet::from(["//:mixed".into()]));
        assert_eq!(mixed.declarations, BTreeSet::from(["//:first".into()]));
        assert!(graph.registration_paths["//:missing"]
            .declarations
            .is_empty());
        let diamond = &graph.registration_paths["//:diamond"];
        assert_eq!(
            diamond.aliases,
            BTreeSet::from(["//:diamond", "//:left", "//:right"].map(str::to_owned))
        );
        assert!(graph.unresolved.contains("//:diamond"));
    }

    #[test]
    fn registered_select_keeps_only_the_branches_supplying_the_required_type() {
        let mut graph = StaticToolchains {
            registration_order: vec!["//:choice".into()],
            aliases: BTreeMap::from([
                (
                    "//:choice".into(),
                    vec!["//:a_alias".into(), "//:b_alias".into()],
                ),
                ("//:a_alias".into(), vec!["//:a".into()]),
                ("//:b_alias".into(), vec!["//:b".into()]),
                ("//:type_alias".into(), vec!["//:type_a".into()]),
            ]),
            declarations: [("//:a", "//:type_alias"), ("//:b", "//:type_b")]
                .into_iter()
                .map(|(name, ty)| {
                    (
                        name.into(),
                        StaticToolchainDeclaration {
                            ty: ty.into(),
                            implementations: BTreeSet::new(),
                            ordinary_inputs: BTreeSet::new(),
                        },
                    )
                })
                .collect(),
            native_types: BTreeSet::from(["//:type_a".into()]),
            ..Default::default()
        };
        // An equal canonical key still supplies a positive match when its type
        // row is missing. The registration's completeness remains unknown.
        graph.index_types(&BTreeSet::from(["//:type_a".into(), "//:type_b".into()]));
        for (ty, alias, declaration) in [
            ("//:type_a", "//:a_alias", "//:a"),
            ("//:type_b", "//:b_alias", "//:b"),
        ] {
            let path = graph.registration_path_for(ty, "//:choice").unwrap();
            assert_eq!(
                path.aliases,
                BTreeSet::from(["//:choice".into(), alias.into()])
            );
            assert_eq!(path.declarations, BTreeSet::from([declaration.into()]));
        }
        assert!(graph.unresolved.contains("//:choice"));
    }

    #[test]
    fn buffa_decodes_delimited_bazel_target() {
        let rule = Rule {
            name: "//foo:bar".into(),
            rule_class: "sh_library".into(),
            ..Default::default()
        };
        let mut target = Target::default();
        target.r#type = target::Discriminator::Rule;
        target.rule = buffa::MessageField::some(rule);
        let path = NamedTempFile::new().unwrap();
        let mut bytes = Vec::new();
        target.encode_length_delimited(&mut bytes);
        fs::write(path.path(), bytes).unwrap();
        let decoded = decode_delimited::<Target>(path.path()).unwrap();
        assert_eq!(target_name(&decoded[0]), Some("//foo:bar"));
    }

    #[test]
    fn target_compaction_retains_hash_inputs() {
        let mut target = Target::default();
        target.r#type = target::Discriminator::Rule;
        target.rule = buffa::MessageField::some(Rule {
            name: "//foo:bar".into(),
            rule_class: "sh_library".into(),
            location: Some("foo/BUILD:1:1".into()),
            attribute: vec![Attribute {
                name: "tags".into(),
                r#type: attribute::Discriminator::StringList,
                string_list_value: vec!["manual".into()],
                ..Default::default()
            }],
            rule_input: vec!["//foo:dep".into()],
            rule_output: vec!["//foo:out".into()],
            default_setting: vec!["unused".into()],
            skylark_environment_hash_code: Some("environment".into()),
            instantiation_stack: vec!["foo/defs.bzl:1:1: macro".into()],
            definition_stack: vec!["unused".into()],
            configured_rule_input: vec![ConfiguredRuleInput {
                label: Some("//foo:dep".into()),
                configuration_checksum: Some("cfg".into()),
                ..Default::default()
            }],
            rule_class_key: Some("unused".into()),
            ..Default::default()
        });

        compact_target(&mut target, false);

        let rule = target.rule.as_option().unwrap();
        assert_eq!(rule.name, "//foo:bar");
        assert_eq!(rule.rule_class, "sh_library");
        assert_eq!(rule.attribute.len(), 1);
        assert_eq!(rule.rule_input, ["//foo:dep"]);
        assert_eq!(
            rule.skylark_environment_hash_code.as_deref(),
            Some("environment")
        );
        assert_eq!(rule.instantiation_stack, ["foo/defs.bzl:1:1: macro"]);
        assert_eq!(rule.configured_rule_input.len(), 1);
        assert!(rule.location.is_none());
        assert!(rule.rule_output.is_empty());
        assert!(rule.default_setting.is_empty());
        assert!(rule.definition_stack.is_empty());
        assert!(rule.rule_class_key.is_none());
    }

    #[test]
    fn source_compaction_retains_name_and_subincludes() {
        let mut target = Target::default();
        target.r#type = target::Discriminator::SourceFile;
        target.source_file = buffa::MessageField::some(SourceFile {
            name: "//foo:bar.txt".into(),
            location: Some("foo/BUILD:1:1".into()),
            subinclude: vec!["//foo:defs.bzl".into()],
            feature: vec!["unused".into()],
            package_contains_errors: Some(true),
            ..Default::default()
        });

        compact_target(&mut target, false);

        let source = target.source_file.as_option().unwrap();
        assert_eq!(source.name, "//foo:bar.txt");
        assert_eq!(source.subinclude, ["//foo:defs.bzl"]);
        assert!(source.location.is_none());
        assert!(source.feature.is_empty());
        assert!(source.package_contains_errors.is_none());
    }

    #[test]
    fn configured_input_includes_checksum() {
        let input = ConfiguredRuleInput {
            label: Some("//foo:bar".into()),
            configuration_checksum: Some("abc".into()),
            ..Default::default()
        };
        assert_eq!(encode_configured_input(&input), "//foo:bar|abc");
        assert_eq!(
            encode_configured_input(&ConfiguredRuleInput {
                label: Some("//foo:bar".into()),
                ..Default::default()
            }),
            "//foo:bar"
        );
    }

    #[test]
    fn main_repo_label_key_puts_main_repository_labels_in_one_form() {
        // Bzlmod, WORKSPACE mode and repr() of a main-repository alias.
        for label in ["@@//pkg:name", "@//pkg:name", "//pkg:name"] {
            assert_eq!(main_repo_label_key(label), "//pkg:name", "{label}");
        }
        assert_eq!(main_repo_label_key("@@//:tool"), "//:tool");
        // External repositories keep their name, in either spelling.
        for label in ["@@rules_cc+//cc:defs", "@rules_cc//cc:defs", "@@foo//:bar"] {
            assert_eq!(main_repo_label_key(label), label, "{label}");
        }
    }

    #[test]
    fn target_names_and_lowering_cover_all_target_types() {
        let source = Target {
            r#type: target::Discriminator::SourceFile,
            source_file: buffa::MessageField::some(SourceFile {
                name: "//pkg:file".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(target_name(&source), Some("//pkg:file"));

        let generated = Target {
            r#type: target::Discriminator::GeneratedFile,
            generated_file: buffa::MessageField::some(GeneratedFile {
                name: "//pkg:generated".into(),
                generating_rule: "//pkg:rule".into(),
                location: Some("pkg/BUILD:1:1".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let generated = lower_target(generated).unwrap();
        assert_eq!(target_name(&generated), Some("//pkg:generated"));
        assert!(generated
            .generated_file
            .as_option()
            .unwrap()
            .location
            .is_none());

        let group = Target {
            r#type: target::Discriminator::PackageGroup,
            package_group: buffa::MessageField::some(PackageGroup {
                name: "//pkg:friends".into(),
                contained_package: vec!["//client/...".into()],
                included_package_group: vec!["//pkg:base".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let group = lower_target(group).unwrap();
        let rule = group.rule.as_option().unwrap();
        assert_eq!(rule.rule_class, "package_group");
        assert_eq!(rule.rule_class_key.as_deref(), Some("package_group"));
        assert!(rule.possible_toolchain_types.as_option().is_none());
        assert_eq!(rule.rule_input, ["//pkg:base"]);
        assert_eq!(rule.attribute[0].string_list_value, ["//client/..."]);

        let mut starlark_group = group;
        starlark_group.rule.as_option_mut().unwrap().rule_class_key =
            Some("@@//pkg:defs.bzl%package_group".into());
        let starlark_group = lower_target(starlark_group).unwrap();
        assert!(starlark_group
            .rule
            .as_option()
            .unwrap()
            .rule_class_key
            .is_none());

        let environment = Target {
            r#type: target::Discriminator::EnvironmentGroup,
            environment_group: buffa::MessageField::some(EnvironmentGroup {
                name: "//pkg:env".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(target_name(&environment), Some("//pkg:env"));
        assert!(lower_target(environment).is_none());

        let missing = Target {
            r#type: target::Discriminator::PackageGroup,
            ..Default::default()
        };
        assert!(lower_target(missing).is_none());
    }

    #[test]
    fn deduplicates_named_targets_and_preserves_first() {
        let first = rule_target("//a:a");
        let mut duplicate = first.clone();
        duplicate.rule.as_option_mut().unwrap().rule_class = "other".into();
        let last = rule_target("//b:b");
        let targets = vec![first.clone(), Target::default(), last.clone(), duplicate];
        assert_eq!(deduplicate_targets(targets).unwrap(), [first, last]);
        assert!(is_external_package_error("no such package 'external'"));
        assert!(is_external_package_error(
            "//external package is not available"
        ));
        assert!(!is_external_package_error("another error"));
    }

    fn test_options(workspace: PathBuf, bazel: PathBuf) -> BazelOptions {
        BazelOptions {
            workspace,
            bazel,
            startup_options: Vec::new(),
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: false,
            cquery_expression: None,
            keep_going: false,
            fine_grained_external_repos: BTreeSet::new(),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: false,
            exclude_targets_query: None,
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        }
    }

    #[test]
    fn server_info_reports_version_output_base_and_external_package() {
        let info = |release: &str, semantics: &str| {
            parse_server_info(&format!(
                "release: {release}\noutput_base: /cache/ob\nstarlark-semantics: {semantics}\n"
            ))
            .unwrap()
        };
        let default = "StarlarkSemantics{internal_bazel_only_utf_8_byte_strings=true}";
        let bazel8 = info("release 8.8.2", default);
        assert_eq!(bazel8.version, Some(BazelVersion(8, 8, 2)));
        assert_eq!(bazel8.output_base, Some(PathBuf::from("/cache/ob")));
        assert_eq!(bazel8.external_package, Some(false));
        assert_eq!(
            info("release 8.8.2", "StarlarkSemantics{enable_workspace=true}").external_package,
            Some(true)
        );
        assert_eq!(info("release 7.4.1", default).external_package, Some(true));
        assert_eq!(
            info("release 7.4.1", "StarlarkSemantics{enable_workspace=false}").external_package,
            Some(false)
        );
        assert_eq!(
            info("release 9.0.0rc1", default).version,
            Some(BazelVersion(9, 0, 0))
        );
        let development = info("development version", default);
        assert_eq!(development.version, None);
        assert_eq!(development.external_package, None);
        assert_eq!(parse_server_info("release: release 8.8.2\n"), None);
    }

    #[test]
    fn server_info_leaves_external_package_open_when_the_query_may_set_it() {
        let workspace = tempfile::tempdir().unwrap();
        let script = workspace.path().join("bazel");
        fs::write(
            &script,
            "#!/bin/sh\nprintf 'release: release 8.8.2\\noutput_base: /ob\\nstarlark-semantics: StarlarkSemantics{}\\n'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut options = test_options(workspace.path().to_path_buf(), script);
        options.no_bazelrc = true;
        assert_eq!(options.server_info().unwrap().external_package, Some(false));
        options.command_options = vec!["--enable_workspace".into()];
        assert_eq!(options.server_info().unwrap().external_package, None);
        options.command_options.clear();
        options.no_bazelrc = false;
        fs::write(
            workspace.path().join(".bazelrc"),
            "try-import %workspace%/user.bazelrc\n",
        )
        .unwrap();
        fs::write(
            workspace.path().join("user.bazelrc"),
            "query --enable_workspace\n",
        )
        .unwrap();
        assert_eq!(options.server_info().unwrap().external_package, None);
    }

    #[test]
    fn known_missing_external_package_is_not_queried() {
        let options = test_options(PathBuf::new(), PathBuf::new());
        let mut queries = Vec::new();
        options
            .collect_all_targets(Vec::new(), Some(false), |expression, _| {
                queries.push(expression.to_owned());
                Ok(vec![rule_target("//app:lib")])
            })
            .unwrap();
        assert_eq!(queries, ["'//...:all-targets'"]);
    }

    #[test]
    fn decodes_query_and_cquery_streams() {
        let directory = tempfile::tempdir().unwrap();
        let query_path = directory.path().join("query.pb");
        write_delimited(&query_path, &[rule_target("//a:a"), rule_target("//b:b")]);
        let mut seen = Vec::new();
        let targets = decode_target_stream(&query_path, &mut |batch| {
            seen.extend(
                batch
                    .iter()
                    .map(|target| target_name(target).unwrap().to_owned()),
            );
        })
        .unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(seen, ["//a:a", "//b:b"]);

        let result = CqueryResult {
            results: vec![ConfiguredTarget {
                target: buffa::MessageField::some(rule_target("//c:c")),
                ..Default::default()
            }],
            ..Default::default()
        };
        let streamed = directory.path().join("cquery-stream.pb");
        write_delimited(&streamed, std::slice::from_ref(&result));
        assert_eq!(
            target_name(&decode_cquery_stream(&streamed, true, &mut |_| {}).unwrap()[0]),
            Some("//c:c")
        );

        let non_streamed = directory.path().join("cquery.pb");
        fs::write(&non_streamed, result.encode_to_vec()).unwrap();
        assert_eq!(
            target_name(&decode_cquery_stream(&non_streamed, false, &mut |_| {}).unwrap()[0]),
            Some("//c:c")
        );
    }

    #[test]
    fn read_message_length_parses_varints_and_rejects_bad_prefixes() {
        assert_eq!(read_message_length(&mut [].as_slice()).unwrap(), None);
        assert_eq!(
            read_message_length(&mut [0x05].as_slice()).unwrap(),
            Some(5)
        );
        // 300 encodes as two continuation-flagged bytes.
        assert_eq!(
            read_message_length(&mut [0xAC, 0x02].as_slice()).unwrap(),
            Some(300)
        );
        // Continuation bit set with nothing following.
        assert!(read_message_length(&mut [0x80].as_slice()).is_err());
        // Never-terminating prefix overflows the shift.
        assert!(read_message_length(&mut [0x80; 10].as_slice()).is_err());
        let mut overflow = [0x80; 10];
        overflow[9] = 0x02;
        assert!(read_message_length(&mut overflow.as_slice()).is_err());
        // 2 GiB is one byte over the protobuf limit.
        assert!(read_message_length(&mut [0x80, 0x80, 0x80, 0x80, 0x08].as_slice()).is_err());
    }

    #[test]
    fn decode_target_stream_preserves_order_across_batches() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("query.pb");
        let written = (0..DECODE_BATCH_MESSAGES + 5)
            .map(|index| rule_target(&format!("//pkg:target{index}")))
            .collect::<Vec<_>>();
        write_delimited(&path, &written);
        assert_eq!(decode_delimited::<Target>(&path).unwrap(), written);
        let mut seen = Vec::new();
        let decoded = decode_target_stream(&path, &mut |batch| {
            seen.extend(
                batch
                    .iter()
                    .map(|target| target_name(target).unwrap().to_owned()),
            );
        })
        .unwrap();
        assert_eq!(decoded.len(), written.len());
        // Order must survive the batch boundary in both the returned targets and
        // the sequence `transform` observes.
        let expected = (0..written.len())
            .map(|index| format!("//pkg:target{index}"))
            .collect::<Vec<_>>();
        assert_eq!(seen, expected);
        assert_eq!(
            decoded
                .iter()
                .map(|target| target_name(target).unwrap().to_owned())
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn delimited_repositories_preserve_duplicates_and_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("repositories.pb");
        // Alternate duplicates, a different value for an unknown field, and an empty record.
        let bytes = [
            6, 0x0a, 1, b'r', 0xa0, 6, 7, 6, 0x0a, 1, b'r', 0xa0, 6, 8, 0, 6, 0x0a, 1, b'r', 0xa0,
            6, 7,
        ];
        fs::write(&path, bytes).unwrap();

        let mut input = bytes.as_slice();
        let mut expected = Vec::new();
        while !input.is_empty() {
            expected.push(
                buffa::DecodeOptions::new()
                    .decode_length_delimited_reader::<Repository>(&mut input)
                    .unwrap(),
            );
        }
        assert_eq!(expected.len(), 4);
        assert_eq!(decode_delimited::<Repository>(&path).unwrap(), expected);
    }

    #[test]
    fn decode_target_stream_rejects_truncated_message() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("truncated.pb");
        // A length prefix of 16 followed by only two bytes of payload.
        fs::write(&path, [0x10u8, 0x00, 0x00]).unwrap();
        assert!(decode_target_stream(&path, &mut |_| {}).is_err());
        assert!(decode_delimited::<Repository>(&path).is_err());
        // One empty repository followed by a complete frame containing an invalid wire tag.
        fs::write(&path, [0x00, 0x01, 0x00]).unwrap();
        assert!(decode_delimited::<Repository>(&path).is_err());
    }

    #[test]
    fn module_edges_are_parsed_and_cycles_broken() {
        let graph = r#"noise
        {
          "name":"root",
          "dependencies":[
            {"name":"a","dependencies":[{"name":"b","dependencies":[{"name":"a","dependencies":[]}]}]},
            {"name":"c","dependencies":[]}
          ]
        }"#;
        let edges = parse_module_dependency_edges(graph);
        assert_eq!(edges["root"], BTreeSet::from(["a".into(), "c".into()]));
        assert_eq!(edges["a"], BTreeSet::from(["b".into()]));
        assert!(edges["b"].is_empty());
        assert!(edges["c"].is_empty());
        assert!(parse_module_dependency_edges("not json").is_empty());
        assert!(parse_module_dependency_edges(r#"{"dependencies":[]}"#).is_empty());
    }

    #[test]
    fn repository_paths_under_the_workspace_hash_relative_to_it() {
        fn string(name: &str, value: &str) -> Attribute {
            Attribute {
                name: name.into(),
                r#type: attribute::Discriminator::String,
                string_value: Some(value.into()),
                ..Default::default()
            }
        }
        // The same repository in two checkouts: a crate built from `vendored/`, which the rule
        // names by absolute path, plus an absolute path outside the workspace.
        let checkout = || {
            let workspace = tempfile::tempdir().unwrap();
            fs::create_dir_all(workspace.path().join("vendored/src")).unwrap();
            fs::write(workspace.path().join("vendored/src/lib.rs"), "v1").unwrap();
            workspace
        };
        let crate_repository = |workspace: &Path| Repository {
            repo_rule_name: Some("local_crate_repository".into()),
            attribute: vec![
                string("path", &format!("{}/vendored", workspace.display())),
                string("toolchain", "/opt/toolchain"),
            ],
            ..Default::default()
        };
        let first = checkout();
        let second = checkout();
        let hashed_attributes = |workspace: &Path| {
            let target = prepared_target(
                &crate_repository(workspace),
                "dep",
                &BTreeSet::new(),
                None,
                &RepositoryWorkspace::new(workspace),
            );
            target.rule.as_option().unwrap().attribute.clone()
        };
        assert_eq!(
            hashed_attributes(first.path()),
            hashed_attributes(second.path())
        );
        assert_eq!(
            prepared_definition_hash(
                &crate_repository(first.path()),
                &RepositoryWorkspace::new(first.path())
            ),
            prepared_definition_hash(
                &crate_repository(second.path()),
                &RepositoryWorkspace::new(second.path())
            )
        );
        // A path outside the workspace keeps its spelling.
        let mut relative = crate_repository(first.path()).attribute;
        normalize_workspace_attributes(&mut relative, &workspace_roots(first.path()));
        assert_eq!(
            relative[0].string_value.as_deref(),
            Some("%workspace%/vendored")
        );
        assert_eq!(relative[1].string_value.as_deref(), Some("/opt/toolchain"));
    }

    #[test]
    fn only_paths_rooted_at_the_workspace_are_rewritten() {
        let roots = vec!["/checkout/repo".to_owned()];
        for (value, expected) in [
            ("/checkout/repo", "%workspace%"),
            ("/checkout/repo/vendored", "%workspace%/vendored"),
            (
                "file:///checkout/repo/registry/x.patch",
                "file://%workspace%/registry/x.patch",
            ),
            // Paths that only contain the workspace's spelling, or share its prefix.
            (
                "/external/checkout/repo/data",
                "/external/checkout/repo/data",
            ),
            (
                "file:///external/checkout/repo/data",
                "file:///external/checkout/repo/data",
            ),
            ("/checkout/repo-other/data", "/checkout/repo-other/data"),
            ("-L/checkout/repo/lib", "-L/checkout/repo/lib"),
        ] {
            assert_eq!(workspace_relative(value, &roots), expected, "{value}");
        }
        // Two different paths outside two checkouts stay different.
        assert_ne!(
            workspace_relative("/data/a/repo/x", &["/a/repo".to_owned()]),
            workspace_relative("/data/b/repo/x", &["/b/repo".to_owned()])
        );
        // `..` that stays inside is fine; `..` that leaves is not.
        assert_eq!(
            workspace_relative("/checkout/repo/a/../b", &roots),
            "%workspace%/a/../b"
        );
        assert_eq!(
            workspace_relative("/checkout/repo/../data", &roots),
            "/checkout/repo/../data"
        );
        assert_eq!(
            workspace_relative("/checkout/repo/a/../../data", &roots),
            "/checkout/repo/a/../../data"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_workspace_is_not_rewritten() {
        let outside = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("inside")).unwrap();
        std::os::unix::fs::symlink(outside.path(), workspace.path().join("link")).unwrap();
        let roots = workspace_roots(workspace.path());
        let root = &roots[0];
        assert_eq!(
            workspace_relative(&format!("{root}/inside/data"), &roots),
            "%workspace%/inside/data"
        );
        let escaping = format!("{root}/link/data");
        assert_eq!(workspace_relative(&escaping, &roots), escaping);
    }

    #[test]
    fn local_repository_hash_is_stable_and_ignores_lockfile() {
        let workspace = tempfile::tempdir().unwrap();
        let repository_root = workspace.path().join("local");
        fs::create_dir(&repository_root).unwrap();
        fs::write(repository_root.join("a.txt"), "a").unwrap();
        fs::write(repository_root.join("MODULE.bazel.lock"), "one").unwrap();
        let repository = Repository {
            repo_rule_name: Some("local_repository".into()),
            attribute: vec![Attribute {
                name: "path".into(),
                r#type: attribute::Discriminator::String,
                string_value: Some("local".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let first = local_repository_content_hash(&repository, workspace.path()).unwrap();
        fs::write(repository_root.join("MODULE.bazel.lock"), "two").unwrap();
        assert_eq!(
            local_repository_content_hash(&repository, workspace.path()).unwrap(),
            first
        );
        fs::write(repository_root.join("a.txt"), "changed").unwrap();
        assert_ne!(
            local_repository_content_hash(&repository, workspace.path()).unwrap(),
            first
        );

        let target = prepared_target(
            &repository,
            "local",
            &BTreeSet::from(["dep".to_owned(), "local".to_owned()]),
            None,
            &RepositoryWorkspace::new(workspace.path()),
        );
        let rule = target.rule.as_option().unwrap();
        assert_eq!(rule.name, "//external:local");
        assert_eq!(rule.rule_class, "local_repository");
        assert_eq!(rule.rule_input, ["//external:dep"]);
        assert!(rule
            .attribute
            .iter()
            .any(|attribute| attribute.name == "_bazel_diff_content_hash"));

        assert!(local_repository_content_hash(&Repository::default(), workspace.path()).is_none());
    }

    #[test]
    fn repository_hash_covers_main_repo_files_named_by_attributes() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir_all(workspace.path().join("third_party/overlay")).unwrap();
        fs::write(workspace.path().join("dep.patch"), "patch v1").unwrap();
        fs::write(workspace.path().join("third_party/dep.BUILD"), "build").unwrap();
        fs::write(
            workspace.path().join("third_party/overlay/BUILD.bazel"),
            "overlay",
        )
        .unwrap();
        let repository = Repository {
            repo_rule_name: Some("http_archive".into()),
            attribute: vec![
                Attribute {
                    name: "urls".into(),
                    r#type: attribute::Discriminator::StringList,
                    string_list_value: vec!["https://example.com/dep.tar.gz".into()],
                    ..Default::default()
                },
                Attribute {
                    name: "patches".into(),
                    r#type: attribute::Discriminator::LabelList,
                    string_list_value: vec!["@@//:dep.patch".into(), "//:missing.patch".into()],
                    ..Default::default()
                },
                Attribute {
                    name: "build_file".into(),
                    r#type: attribute::Discriminator::Label,
                    string_value: Some("//third_party:dep.BUILD".into()),
                    ..Default::default()
                },
                Attribute {
                    name: "overlay".into(),
                    r#type: attribute::Discriminator::LabelDictUnary,
                    label_dict_unary_value: vec![LabelDictUnaryEntry {
                        key: "//third_party:overlay".into(),
                        value: "BUILD.bazel".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            repository_local_input_labels(&repository),
            BTreeSet::from([
                "@@//:dep.patch",
                "//:missing.patch",
                "//third_party:dep.BUILD",
                "//third_party:overlay",
            ])
        );
        let baseline = repository_local_inputs_hash(&repository, workspace.path()).unwrap();
        assert_eq!(
            repository_local_inputs_hash(&repository, workspace.path()).unwrap(),
            baseline
        );

        // Patch content, the build file, and the overlay directory all reach the hash.
        fs::write(workspace.path().join("dep.patch"), "patch v2").unwrap();
        let patched = repository_local_inputs_hash(&repository, workspace.path()).unwrap();
        assert_ne!(patched, baseline);
        fs::write(workspace.path().join("third_party/dep.BUILD"), "build v2").unwrap();
        let rebuilt = repository_local_inputs_hash(&repository, workspace.path()).unwrap();
        assert_ne!(rebuilt, patched);
        fs::write(
            workspace.path().join("third_party/overlay/BUILD.bazel"),
            "overlay v2",
        )
        .unwrap();
        assert_ne!(
            repository_local_inputs_hash(&repository, workspace.path()).unwrap(),
            rebuilt
        );

        let target = prepared_target(
            &repository,
            "dep",
            &BTreeSet::new(),
            None,
            &RepositoryWorkspace::new(workspace.path()),
        );
        let rule = target.rule.as_option().unwrap();
        assert!(rule
            .attribute
            .iter()
            .any(|attribute| attribute.name == "_bazel_diff_local_inputs_hash"));

        // A repository whose attributes name no workspace file carries no such attribute.
        let remote_only = Repository {
            repo_rule_name: Some("http_archive".into()),
            attribute: vec![Attribute {
                name: "patches".into(),
                r#type: attribute::Discriminator::LabelList,
                string_list_value: vec!["@other//:dep.patch".into(), "//:missing.patch".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(repository_local_inputs_hash(&remote_only, workspace.path()).is_none());
        let target = prepared_target(
            &remote_only,
            "dep",
            &BTreeSet::new(),
            None,
            &RepositoryWorkspace::new(workspace.path()),
        );
        assert!(!target
            .rule
            .as_option()
            .unwrap()
            .attribute
            .iter()
            .any(|attribute| attribute.name == "_bazel_diff_local_inputs_hash"));
    }

    #[test]
    fn parses_versions_and_exclude_filters() {
        assert_eq!(
            parse_bazel_version("Build label: 8.6.1-pre.2026\n"),
            Some(BazelVersion(8, 6, 1))
        );
        assert_eq!(
            parse_bazel_version("bazel 7.0.0\n"),
            Some(BazelVersion(7, 0, 0))
        );
        assert_eq!(parse_bazel_version("unexpected"), None);

        let mut options = BazelOptions {
            workspace: PathBuf::new(),
            bazel: PathBuf::new(),
            startup_options: Vec::new(),
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: false,
            cquery_expression: None,
            keep_going: false,
            fine_grained_external_repos: BTreeSet::new(),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: false,
            exclude_targets_query: None,
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        };
        options.exclude_targets_query = Some("attr(tags, manual, //...)".into());
        assert_eq!(
            options.with_exclude_filter("//...".into()),
            "(//...) except (attr(tags, manual, //...))"
        );
        options.exclude_targets_query = Some(" ".into());
        assert_eq!(options.with_exclude_filter("//...".into()), "//...");
    }

    #[test]
    fn query_collection_retries_without_external_and_deduplicates() {
        let options = BazelOptions {
            workspace: PathBuf::new(),
            bazel: PathBuf::new(),
            startup_options: Vec::new(),
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: false,
            cquery_expression: None,
            keep_going: false,
            fine_grained_external_repos: BTreeSet::from(["@repo".to_owned()]),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: false,
            exclude_targets_query: Some("attr(tags, manual, //...)".into()),
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        };
        let mut queries = Vec::new();
        let targets = options
            .collect_all_targets(
                vec![rule_target("//external:bzlmod")],
                None,
                |expression, cquery| {
                    queries.push((expression.to_owned(), cquery));
                    if queries.len() == 1 {
                        Err(anyhow!("no such package 'external'"))
                    } else {
                        Ok(vec![rule_target("//app:lib"), rule_target("//app:lib")])
                    }
                },
            )
            .unwrap();
        assert_eq!(queries.len(), 2);
        assert!(queries[0].0.contains("//external:all-targets"));
        assert!(!queries[1].0.contains("//external:all-targets"));
        assert!(queries[1].0.contains("@repo//...:all-targets"));
        assert!(queries[1].0.contains("except (attr(tags, manual, //...))"));
        assert_eq!(
            targets.iter().filter_map(target_name).collect::<Vec<_>>(),
            ["//app:lib", "//external:bzlmod"]
        );
    }

    #[test]
    fn cquery_collection_drops_missing_external_package() {
        let options = BazelOptions {
            workspace: PathBuf::new(),
            bazel: PathBuf::new(),
            startup_options: Vec::new(),
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: true,
            cquery_expression: Some("deps(//app:lib)".into()),
            keep_going: false,
            fine_grained_external_repos: BTreeSet::new(),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: false,
            exclude_targets_query: None,
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        };
        let mut queries = Vec::new();
        let targets = options
            .collect_all_targets(Vec::new(), None, |expression, cquery| {
                queries.push((expression.to_owned(), cquery));
                if cquery {
                    Ok(vec![rule_target("//app:lib")])
                } else {
                    Err(anyhow!("//external package is not available"))
                }
            })
            .unwrap();
        assert_eq!(
            queries,
            vec![
                ("deps(//app:lib)".to_owned(), true),
                ("'//external:all-targets'".to_owned(), false),
            ]
        );
        assert_eq!(target_name(&targets[0]), Some("//app:lib"));
    }

    #[test]
    fn repository_mapping_and_lowering_are_deterministic() {
        let mapping = parse_repo_mapping(
            r#"not json
{"dep":"dep+1.0","alias":"dep+1.0","child":"child+2.0","tools":"bazel_tools","local":"local_config_platform","":""}
"#,
        );
        assert_eq!(mapping["dep+1.0"], ["alias".to_owned(), "dep".to_owned()]);
        assert_eq!(mapping["child+2.0"], ["child"]);
        assert!(!mapping.contains_key("bazel_tools"));

        let repositories = vec![
            Repository {
                canonical_name: Some("dep+1.0".into()),
                repo_rule_name: Some("http_archive".into()),
                ..Default::default()
            },
            Repository {
                canonical_name: Some("child+2.0".into()),
                repo_rule_name: Some("git_repository".into()),
                ..Default::default()
            },
        ];
        let edges = BTreeMap::from([("dep".to_owned(), BTreeSet::from(["child".to_owned()]))]);
        let mut transformed = Vec::new();
        let targets = lower_repositories(
            repositories,
            &mapping,
            &edges,
            None,
            &LabelOnlyRepositories::default(),
            Path::new("."),
            &mut |target, _| transformed.push(target_name(target).unwrap().to_owned()),
        );
        assert_eq!(targets.len(), 3);
        assert_eq!(
            transformed,
            ["//external:alias", "//external:dep", "//external:child"]
        );
        let dep = targets
            .iter()
            .find(|target| target_name(target) == Some("//external:dep"))
            .unwrap()
            .rule
            .as_option()
            .unwrap();
        assert_eq!(dep.rule_class, "http_archive");
        assert_eq!(dep.rule_input, ["//external:child"]);
    }

    #[test]
    fn apparent_names_share_one_read_of_the_repository_inputs() {
        let workspace = tempfile::tempdir().unwrap();
        let patch = workspace.path().join("dep.patch");
        fs::write(&patch, "first").unwrap();
        let patched = |canonical: &str| Repository {
            canonical_name: Some(canonical.into()),
            attribute: vec![Attribute {
                name: "patches".into(),
                r#type: attribute::Discriminator::LabelList,
                string_list_value: vec!["//:dep.patch".into()],
                ..Default::default()
            }],
            ..Default::default()
        };

        let first = repository_local_inputs_hash(&patched("dep+"), workspace.path()).unwrap();
        let targets = lower_repositories(
            vec![
                Repository {
                    canonical_name: Some("before+".into()),
                    ..Default::default()
                },
                patched("dep+"),
                patched("dep++ext+spoke"),
            ],
            &parse_repo_mapping(r#"{"before":"before+","a":"dep+","b":"dep+"}"#),
            &BTreeMap::new(),
            Some(&BTreeSet::new()),
            &LabelOnlyRepositories::default(),
            workspace.path(),
            &mut |target, _| {
                // The module definitions have been hashed, but dep's targets have not been emitted.
                if target_name(target) == Some("//external:before") {
                    fs::write(&patch, "second").unwrap();
                }
            },
        );
        let second = repository_local_inputs_hash(&patched("dep+"), workspace.path()).unwrap();
        assert_ne!(first, second);
        let observed: Vec<_> = targets
            .iter()
            .map(|target| {
                let digest = target
                    .rule
                    .as_option()
                    .unwrap()
                    .attribute
                    .iter()
                    .find(|attr| attr.name == "_bazel_diff_local_inputs_hash")
                    .and_then(|attr| attr.string_value.as_deref());
                (target_name(target).unwrap(), digest)
            })
            .collect();
        let first = Some(first.as_str());
        assert_eq!(
            observed,
            [
                ("//external:before", None),
                ("//external:!unresolved-module-dep+!a", None),
                ("//external:a", first),
                ("//external:!unresolved-module-dep+!b", None),
                ("//external:b", first),
                ("//external:dep++ext+spoke", Some(second.as_str())),
            ]
        );
    }

    /// Issue #522: a module pinned with `single_version_override(patches = ["//:dep.patch"])`
    /// is shown by `bazel mod show_repo` as an `http_archive` whose `patches` name a main-repo
    /// file. Its node is `//external:dep`, named by the root's apparent name and not by the
    /// canonical `dep+` cquery prints, and the patch content is part of the node's hash even
    /// though the patch touches no `.bzl` file.
    #[test]
    fn single_version_override_patch_is_hashed_into_the_apparent_repository_node() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(
            workspace.path().join("dep.patch"),
            "--- a/data.txt\n+++ b/data.txt\n@@ -1 +1 @@\n-original\n+patched v1\n",
        )
        .unwrap();
        let mapping = parse_repo_mapping(r#"{"":"","dep":"dep+","bazel_tools":"bazel_tools"}"#);
        let repository = || Repository {
            canonical_name: Some("dep+".into()),
            repo_rule_name: Some("http_archive".into()),
            attribute: vec![
                Attribute {
                    name: "urls".into(),
                    r#type: attribute::Discriminator::StringList,
                    string_list_value: vec!["file:/registry/dep.zip".into()],
                    ..Default::default()
                },
                Attribute {
                    name: "patches".into(),
                    r#type: attribute::Discriminator::LabelList,
                    string_list_value: vec!["//:dep.patch".into()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let lower = || {
            let targets = lower_repositories(
                vec![repository()],
                &mapping,
                &BTreeMap::new(),
                None,
                &LabelOnlyRepositories::default(),
                workspace.path(),
                &mut materialize_repository_inputs,
            );
            assert_eq!(targets.len(), 1);
            let rule = targets[0].rule.as_option().unwrap().clone();
            assert_eq!(rule.name, "//external:dep");
            rule.attribute
                .iter()
                .find(|attribute| attribute.name == "_bazel_diff_local_inputs_hash")
                .and_then(|attribute| attribute.string_value.clone())
                .expect("patch hashed into the node")
        };
        let before = lower();
        fs::write(
            workspace.path().join("dep.patch"),
            "--- a/data.txt\n+++ b/data.txt\n@@ -1 +1 @@\n-original\n+patched v2\n",
        )
        .unwrap();
        assert_ne!(lower(), before);
    }

    #[test]
    fn modules_hidden_from_the_root_stay_on_the_repository_path() {
        // Issue #510: root -> facade -> middle (apparent name only inside facade) -> leaf.
        let mapping = parse_repo_mapping(
            r#"{"":"","facade":"facade+","leaf":"leaf+","ext_repo":"+ext+repo","bazel_tools":"bazel_tools"}"#,
        );
        let graph = r#"{
          "key":"<root>","name":"root","dependencies":[
            {"key":"facade@_","name":"facade","dependencies":[
              {"key":"middle@_","name":"middle","dependencies":[
                {"key":"leaf@_","name":"leaf","dependencies":[]}]}]},
            {"key":"leaf@_","name":"leaf","dependencies":[]}
          ]
        }"#;
        assert_eq!(
            hidden_module_repo_names(graph, &mapping),
            BTreeMap::from([("middle@_".to_owned(), "middle+".to_owned())])
        );
        assert!(hidden_module_repo_names("not json", &mapping).is_empty());

        let repositories = ["facade+", "middle+", "leaf+"]
            .into_iter()
            .map(|canonical| Repository {
                canonical_name: Some(canonical.into()),
                repo_rule_name: Some("http_archive".into()),
                ..Default::default()
            })
            .collect();
        let targets = lower_repositories(
            repositories,
            &mapping,
            &parse_module_dependency_edges(graph),
            None,
            &LabelOnlyRepositories::default(),
            Path::new("."),
            &mut materialize_repository_inputs,
        );
        let inputs = |name: &str| {
            targets
                .iter()
                .find(|target| target_name(target) == Some(name))
                .unwrap()
                .rule
                .as_option()
                .unwrap()
                .rule_input
                .clone()
        };
        assert_eq!(inputs("//external:facade"), ["//external:middle+"]);
        assert_eq!(inputs("//external:middle+"), ["//external:leaf"]);
        assert!(inputs("//external:leaf").is_empty());
    }

    #[test]
    fn extension_repo_names_identify_usage_and_owner() {
        assert!(is_extension_repo("rules_go++go_sdk+go_default_sdk"));
        assert!(is_extension_repo("platforms+host_platform+host_platform"));
        assert!(is_extension_repo("+ext+repo"));
        assert!(!is_extension_repo("rules_go+"));
        assert!(!is_extension_repo("dep+1.0"));
        assert!(!is_extension_repo("platforms"));
        let cases = [
            (
                "rules_go++go_sdk+go_default_sdk",
                "rules_go+",
                "rules_go++go_sdk",
            ),
            ("dep+1.0+ext+repo", "dep+1.0", "dep+1.0+ext"),
            (
                "platforms+host_platform+host_platform",
                "platforms",
                "platforms+host_platform",
            ),
            ("+ext+repo", "", "+ext"),
        ];
        let module_definitions = cases
            .iter()
            .map(|(_canonical, owner, _prefix)| ((*owner).to_owned(), String::new()))
            .collect();
        for (canonical, owner, prefix) in cases {
            assert_eq!(extension_usage_prefix(canonical), Some(prefix));
            assert_eq!(
                extension_repo_owner(prefix, &module_definitions)
                    .map(|(owner, _definition_hash)| owner.as_str()),
                Some(owner)
            );
        }
        assert_eq!(extension_usage_prefix("rules_go+"), None);
    }

    #[test]
    fn arguments_are_chunked_by_byte_budget() {
        let names = ["aaaa", "bbbb", "cccc", "dddd", "e"]
            .map(str::to_owned)
            .to_vec();
        assert_eq!(
            chunk_arguments(&names, 10),
            [&names[0..2], &names[2..4], &names[4..]]
        );
        // One oversized argument still travels, on its own.
        assert_eq!(chunk_arguments(&names, 3).len(), 5);
        assert_eq!(chunk_arguments(&names, 1000), [&names[..]]);
        assert!(chunk_arguments(&[], 10).is_empty());
    }

    #[test]
    fn argument_budget_defaults_unless_the_environment_sets_a_positive_count() {
        assert_eq!(
            mod_argument_byte_budget_from(None),
            DEFAULT_MOD_ARGUMENT_BYTE_BUDGET
        );
        assert_eq!(mod_argument_byte_budget_from(Some(" 4096 ")), 4096);
        for junk in ["", "0", "-1", "lots", "6K"] {
            assert_eq!(
                mod_argument_byte_budget_from(Some(junk)),
                DEFAULT_MOD_ARGUMENT_BYTE_BUDGET,
                "{junk:?}"
            );
        }
    }

    /// A fake Bazel for `show_repo`: by name it prints `<dir>/<name>.pb` for each name
    /// given; `--all_repos` prints `<dir>/all.pb`, or fails with `<dir>/all-repos.stderr`
    /// when that file exists. Every invocation is appended to `<dir>/calls.log`.
    #[cfg(unix)]
    fn show_repo_script(dir: &Path, by_name: &[Repository], all: &[Repository]) -> PathBuf {
        for repository in by_name {
            let name = repository
                .module_key
                .clone()
                .unwrap_or_else(|| format!("@@{}", repository.canonical_name.as_deref().unwrap()));
            write_delimited(
                &dir.join(format!("{name}.pb")),
                std::slice::from_ref(repository),
            );
        }
        write_delimited(&dir.join("all.pb"), all);
        let script = dir.join("fake-bazel.sh");
        let body = format!(
            r#"#!/bin/sh
echo "$*" >> "{dir}/calls.log"
if [ "$1" = "mod" ] && [ "$2" = "show_repo" ]; then
  shift 2
  if [ "$1" = "--all_repos" ]; then
    if [ -f "{dir}/all-repos.stderr" ]; then
      cat "{dir}/all-repos.stderr" >&2
      exit 2
    fi
    cat "{dir}/all.pb"
    exit 0
  fi
  for name in "$@"; do
    case "$name" in
      --*) ;;
      *) cat "{dir}/$name.pb" ;;
    esac
  done
  exit 0
fi
exit 1
"#,
            dir = dir.display(),
        );
        fs::write(&script, &body).unwrap();
        script
    }

    #[cfg(unix)]
    fn canonical_names(repositories: &[Repository]) -> Vec<&str> {
        repositories
            .iter()
            .filter_map(|repository| repository.canonical_name.as_deref())
            .collect()
    }

    #[cfg(unix)]
    fn show_repo_calls(dir: &Path) -> Vec<String> {
        fs::read_to_string(dir.join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[cfg(unix)]
    fn repository(canonical: &str) -> Repository {
        Repository {
            canonical_name: Some(canonical.into()),
            repo_rule_name: Some("http_archive".into()),
            ..Default::default()
        }
    }

    #[test]
    #[cfg(unix)]
    fn large_repository_reads_preserve_selected_records() {
        let workspace = tempfile::tempdir().unwrap();
        let wanted = ["a+", "b+", "c++ext+x"].map(repository);
        let mut bulk_hidden = repository("hidden+");
        bulk_hidden.original_name = Some("upstream_name".into());
        let mut hidden = bulk_hidden.clone();
        hidden.module_key = Some("hidden@1.0".to_owned());
        let mut by_name = wanted.to_vec();
        by_name.push(hidden.clone());
        // `--all_repos` answers with more than was asked: the main-visible `bazel_tools` and
        // a repository nothing imports. Its hidden module record has no module key.
        let mut all = vec![
            repository("bazel_tools"),
            repository("unasked++ext+y"),
            repository("failed++ext+x"),
            bulk_hidden,
        ];
        all.extend(wanted.iter().rev().cloned());
        let script = show_repo_script(workspace.path(), &by_name, &all);
        // RepoOverride produces no streamed proto record in either mode.
        write_delimited(
            &workspace.path().join("@@omitted+.pb"),
            &[] as &[Repository],
        );
        let options = BazelOptions {
            workspace: workspace.path().to_path_buf(),
            bazel: PathBuf::from("/bin/sh"),
            startup_options: vec![script.to_str().unwrap().to_owned()],
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: false,
            cquery_expression: None,
            keep_going: false,
            fine_grained_external_repos: BTreeSet::new(),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: true,
            exclude_targets_query: None,
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        };
        let names = [
            "@@a+",
            "@@b+",
            "@@c++ext+x",
            "@@failed++ext+x",
            "@@omitted+",
            "hidden@1.0",
        ]
        .map(str::to_owned)
        .to_vec();
        let expected = wanted
            .into_iter()
            .chain(std::iter::once(hidden))
            .collect::<Vec<_>>();
        let original_failed = FailedExtensions {
            observed: true,
            extensions: BTreeSet::from(["@@failed+//:ext.bzl%ext".to_owned()]),
            unavailable: BTreeSet::from(["failed++ext+x".to_owned()]),
        };
        let mut failed = original_failed.clone();
        let bindings = BTreeMap::from([("hidden@1.0".into(), "hidden+".into())]);

        // Canonical names use one bulk invocation; the hidden module retains its explicit record.
        let repositories = options
            .show_repositories_within(&names, &mut failed, 8, || {
                panic!("partial bulk output must not inspect hidden bindings")
            })
            .unwrap();
        assert_eq!(repositories, expected);
        let calls = show_repo_calls(workspace.path());
        assert_eq!(
            calls,
            [
                "mod show_repo --all_repos --output=streamed_proto",
                "mod show_repo hidden@1.0 --output=streamed_proto",
            ],
            "{calls:?}"
        );
        assert_eq!(failed, original_failed);

        // Names that fit one invocation are still asked for by name.
        let repositories = options
            .show_repositories_within(&names, &mut failed, 1000, || {
                panic!("small selections must not inspect hidden bindings")
            })
            .unwrap();
        assert_eq!(repositories, expected);
        let calls = show_repo_calls(workspace.path());
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert_eq!(
            calls[2],
            "mod show_repo @@a+ @@b+ @@c++ext+x @@omitted+ hidden@1.0 --output=streamed_proto"
        );

        // A healthy bulk read can supply the same module-key record, byte for byte.
        let clean: Vec<_> = names
            .into_iter()
            .filter(|name| !name.starts_with("@@failed+"))
            .collect();
        let actual = options
            .show_repositories_within(&clean, &mut FailedExtensions::default(), 8, || {
                Some(&bindings)
            })
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            &show_repo_calls(workspace.path())[3..],
            ["mod show_repo --all_repos --output=streamed_proto"]
        );
    }

    #[test]
    fn hidden_module_keys_follow_each_parents_actual_alias() {
        let graph = r#"{"dependencies":[{"key":"visible@1","apparentName":"alias","dependencies":[{"key":"hidden@2","apparentName":"other_alias"}]},{"key":"hidden@2","apparentName":"sibling"}]}"#;
        let hidden = BTreeMap::from([("hidden@2".into(), "hidden+".into())]);
        let modules = BTreeMap::from([(
            "visible+".into(),
            BTreeMap::from([("other_alias".into(), "hidden+".into())]),
        )]);
        assert!(verified_hidden_modules(
            Some(graph),
            br#"{"alias":"visible+","sibling":"hidden+"}"#,
            &modules,
            &hidden
        ));
        assert!(!verified_hidden_modules(
            Some(graph),
            br#"{"alias":"visible+","sibling":"different+"}"#,
            &modules,
            &hidden
        ));
        assert!(!verified_hidden_modules(
            Some(graph),
            br#"{"alias":"visible+"}"#,
            &modules,
            &hidden
        ));
    }

    #[test]
    #[cfg(unix)]
    fn incomplete_mapping_rows_remain_unbound() {
        let workspace = tempfile::tempdir().unwrap();
        let script = workspace.path().join("bazel");
        fs::write(&script, "#!/bin/sh\ncat reply\n").unwrap();
        let options = probe_options(workspace.path(), script);
        let names = ["first+", "second+"].map(str::to_owned);
        for (reply, rows, expected_complete) in [
            ("{}\n{}\n", 2, true),
            ("{}\n", 1, false),
            ("{}\ninvalid\n{}\n", 2, false),
            ("{}\n{}\n{}\n", 3, false),
        ] {
            fs::write(workspace.path().join("reply"), reply).unwrap();
            let mut complete = true;
            let mappings = options
                .dump_repo_mappings(&names, &mut FailedExtensions::default(), &mut complete)
                .unwrap();
            assert_eq!(mappings.len(), rows);
            assert_eq!(complete, expected_complete);
        }
    }

    #[test]
    #[cfg(unix)]
    fn mappings_preserve_effective_names_in_each_isolated_extension() {
        let workspace = tempfile::tempdir().unwrap();
        let first = "mod++_ext+owner+1+first+hub";
        let second = "mod++_ext+owner+1+second+hub";
        let library = "mod++_ext+owner+1+first+library";
        let injected = "mod++_ext+owner+1+second+injected";
        for (name, map) in [
            ("dep+", serde_json::json!({"one": first, "two": second})),
            (
                first,
                serde_json::json!({"library": library, "replaced": "other+", "injected": injected}),
            ),
            (
                second,
                serde_json::json!({"other": "unimported++ext+unused"}),
            ),
        ] {
            fs::write(workspace.path().join(name), format!("{map}\n")).unwrap();
        }
        let script = workspace.path().join("bazel");
        fs::write(
            &script,
            "#!/bin/sh\nshift 2\necho \"$*\" >> calls\nfor name do cat \"$name\" || exit 1; done\n",
        )
        .unwrap();
        let options = probe_options(workspace.path(), script);
        let root = BTreeMap::from([
            ("dep+".into(), vec!["dep".into()]),
            (first.into(), vec!["hub".into()]),
        ]);
        let result = options
            .extension_repositories(
                &root,
                Vec::new(),
                BTreeMap::new(),
                true,
                &mut FailedExtensions::default(),
            )
            .unwrap();
        assert_eq!(result.imported, [first, second].map(str::to_owned).into());
        assert_eq!(
            result.generated,
            [first, second, library, injected].map(str::to_owned).into()
        );
        assert_eq!(
            fs::read_to_string(workspace.path().join("calls")).unwrap(),
            format!("dep+\n{first} {second}\n")
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_bazel_without_all_repos_is_asked_by_name_per_chunk() {
        let workspace = tempfile::tempdir().unwrap();
        let mut wanted = ["a+", "b+", "c++ext+x"].map(repository).to_vec();
        let mut hidden = repository("hidden+");
        hidden.module_key = Some("hidden@1.0".to_owned());
        wanted.push(hidden);
        let script = show_repo_script(workspace.path(), &wanted, &[]);
        fs::write(
            workspace.path().join("all-repos.stderr"),
            "ERROR: --all_repos :: Unrecognized option: --all_repos\n",
        )
        .unwrap();
        let options = BazelOptions {
            workspace: workspace.path().to_path_buf(),
            bazel: PathBuf::from("/bin/sh"),
            startup_options: vec![script.to_str().unwrap().to_owned()],
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: false,
            cquery_expression: None,
            keep_going: false,
            fine_grained_external_repos: BTreeSet::new(),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: true,
            exclude_targets_query: None,
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        };
        let names = ["@@a+", "@@b+", "@@c++ext+x", "hidden@1.0"]
            .map(str::to_owned)
            .to_vec();
        let mut failed = FailedExtensions::default();
        let repositories = options
            .show_repositories_within(&names, &mut failed, 8, || None)
            .unwrap();
        assert_eq!(repositories, wanted);
        assert_eq!(
            show_repo_calls(workspace.path()),
            [
                "mod show_repo --all_repos --output=streamed_proto",
                "mod show_repo @@a+ --output=streamed_proto",
                "mod show_repo @@b+ --output=streamed_proto",
                "mod show_repo @@c++ext+x --output=streamed_proto",
                "mod show_repo hidden@1.0 --output=streamed_proto",
            ]
        );
        assert_eq!(failed, FailedExtensions::default());
    }

    #[test]
    #[cfg(unix)]
    fn an_extension_that_spoils_all_repos_is_checked_by_name() {
        let workspace = tempfile::tempdir().unwrap();
        let wanted = ["a+", "b+", "c++ext+x"].map(repository);
        let script = show_repo_script(workspace.path(), &wanted, &[]);
        fs::write(
            workspace.path().join("all-repos.stderr"),
            "ERROR: error evaluating module extension @@c+//:ext.bzl%ext\n",
        )
        .unwrap();
        let options = BazelOptions {
            workspace: workspace.path().to_path_buf(),
            bazel: PathBuf::from("/bin/sh"),
            startup_options: vec![script.to_str().unwrap().to_owned()],
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: false,
            cquery_expression: None,
            keep_going: false,
            fine_grained_external_repos: BTreeSet::new(),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: true,
            exclude_targets_query: None,
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        };
        let names = ["@@a+", "@@b+", "@@c++ext+x"].map(str::to_owned).to_vec();
        let mut failed = FailedExtensions::default();
        let repositories = options
            .show_repositories_within(&names, &mut failed, 8, || None)
            .unwrap();
        assert_eq!(canonical_names(&repositories), ["a+", "b+", "c++ext+x"]);
        assert_eq!(
            failed.extensions,
            BTreeSet::from(["@@c+//:ext.bzl%ext".to_owned()])
        );
        assert!(failed.unavailable.is_empty());
        assert_eq!(
            show_repo_calls(workspace.path()),
            [
                "mod show_repo --all_repos --output=streamed_proto",
                "mod show_repo @@a+ --output=streamed_proto",
                "mod show_repo @@b+ --output=streamed_proto",
                "mod show_repo @@c++ext+x --output=streamed_proto",
            ]
        );
    }

    #[test]
    fn hidden_module_repo_names_follow_bazels_naming() {
        let mapping = parse_repo_mapping(r#"{"":"","facade":"facade+","platforms":"platforms"}"#);
        let graph = r#"{
          "key":"<root>","name":"root","dependencies":[
            {"key":"facade@_","name":"facade","dependencies":[
              {"key":"multi@1.0","name":"multi","dependencies":[]},
              {"key":"multi@2.0","name":"multi","dependencies":[]},
              {"key":"platforms@1.1.0","name":"platforms","dependencies":[]},
              {"key":"bazel_tools@_","name":"bazel_tools","dependencies":[]},
              {"key":"leaf@1.0","name":"leaf","dependencies":[],"cycles":[
                {"key":"facade@_","name":"facade","unexpanded":true}]}]},
            {"key":"leaf@1.0","name":"leaf","unexpanded":true}
          ],
          "indirectDependencies":[{"key":"leaf@1.0","name":"leaf","unexpanded":true}]
        }"#;
        let expected = BTreeMap::from([
            ("bazel_tools@_".to_owned(), "bazel_tools".to_owned()),
            ("leaf@1.0".to_owned(), "leaf+".to_owned()),
            ("multi@1.0".to_owned(), "multi+1.0".to_owned()),
            ("multi@2.0".to_owned(), "multi+2.0".to_owned()),
        ]);
        assert_eq!(hidden_module_repo_names(graph, &mapping), expected);
        assert_eq!(
            isolated_module_repo_names(graph, &mapping).unwrap(),
            expected
        );

        let mut one_version = mapping;
        one_version.insert("multi+1.0".into(), vec!["multi".into()]);
        let legacy = hidden_module_repo_names(graph, &one_version);
        assert_eq!(legacy.get("multi@1.0"), None);
        assert_eq!(legacy.get("multi@2.0"), None);
        let isolated = isolated_module_repo_names(graph, &one_version).unwrap();
        assert_eq!(isolated.get("multi@1.0"), None);
        assert_eq!(
            isolated.get("multi@2.0").map(String::as_str),
            Some("multi+2.0")
        );
    }

    #[test]
    fn required_module_inventory_rejects_unreadable_and_incomplete_graphs() {
        let mapping = BTreeMap::new();
        for (graph, reason) in [
            ("not json", "invalid module graph JSON"),
            (
                r#"{"name":"root","dependencies":[]}"#,
                "missing field `key`",
            ),
            (
                r#"{"key":"other@1","name":"other","dependencies":[]}"#,
                "module graph root key is other@1, expected <root>",
            ),
            (
                r#"{"key":"<root>","name":"root","unexpanded":true}"#,
                "module graph root is unexpanded",
            ),
            (
                r#"{"key":"<root>","name":"root","dependencies":[{"key":"dep@1","dependencies":[]}]}"#,
                "missing field `name`",
            ),
            (
                r#"{"key":"<root>","name":"root","dependencies":{}}"#,
                "expected a sequence",
            ),
            (
                r#"{"key":"<root>","name":"root","dependencies":[{"key":"dep@1","name":"dep","unexpanded":true}]}"#,
                "dep@1 is only an unexpanded reference",
            ),
            (
                r#"{"key":"<root>","name":"root","dependencies":[{"key":"wrong@1","name":"dep","dependencies":[]}]}"#,
                "key wrong@1 does not identify dep@version",
            ),
        ] {
            let error = isolated_module_repo_names(graph, &mapping).unwrap_err();
            assert!(format!("{error:#}").contains(reason), "{error:#}");
        }
        assert!(isolated_module_repo_names(
            r#"{"key":"<root>","name":"","dependencies":[]}"#,
            &mapping
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn isolated_module_graph_requires_utf8() {
        use std::os::unix::process::ExitStatusExt;

        let workspace = tempfile::tempdir().unwrap();
        let mut options = probe_options(workspace.path(), PathBuf::from("unused"));
        let output = || Output {
            status: ExitStatus::from_raw(0),
            stdout: b"{\"key\":\"<root>\",\"name\":\"\xff\",\"dependencies\":[]}".to_vec(),
            stderr: Vec::new(),
        };
        options.isolated_dependency_root = Some("@hub".into());
        let error = options
            .module_graph_json_tolerating(Some(output()), &mut FailedExtensions::default())
            .unwrap_err();
        assert!(error.to_string().contains("not valid UTF-8"), "{error:#}");
        options.isolated_dependency_root = None;
        let (json, complete) = options
            .module_graph_json_tolerating(Some(output()), &mut FailedExtensions::default())
            .unwrap();
        assert!(complete);
        assert!(json.contains('\u{fffd}'));
    }

    #[test]
    fn extension_inventories_are_separate_from_definitions() {
        // Root imports `rules_go` and the `bd_crates` hub of rules_rs' crate extension; rules_go's
        // own module imports `go_toolchains`; nobody imports `go_default_sdk` or the crate spoke.
        let mapping = parse_repo_mapping(
            r#"{"":"","rules_go":"rules_go+","rules_rs":"rules_rs+","bd_crates":"rules_rs++crate+bd_crates"}"#,
        );
        let imported = BTreeSet::from([
            "rules_rs++crate+bd_crates".to_owned(),
            "rules_go++go_sdk+go_toolchains".to_owned(),
        ]);
        let repositories = || {
            [
                "rules_go+",
                "rules_rs+",
                "rules_rs++crate+bd_crates",
                "rules_rs++crate+bd_crates__anyhow-1.0.104",
                // An isolated root usage adds empty module/version components and its exported name.
                "rules_rs++_crate+++isolated_crates+crate_repo",
                "rules_go++go_sdk+go_toolchains",
                "rules_go++go_sdk+go_default_sdk",
                "+local+root_ext_repo",
            ]
            .into_iter()
            .map(|canonical| Repository {
                canonical_name: Some(canonical.into()),
                repo_rule_name: Some("http_archive".into()),
                ..Default::default()
            })
            .collect::<Vec<_>>()
        };
        let edges = BTreeMap::from([(
            "rules_go".to_owned(),
            BTreeSet::from(["rules_rs".to_owned()]),
        )]);
        let inputs_of = |targets: &[Target], name: &str| {
            targets
                .iter()
                .find(|target| target_name(target) == Some(name))
                .unwrap_or_else(|| panic!("{name} missing"))
                .rule
                .as_option()
                .unwrap()
                .rule_input
                .clone()
        };

        let query = lower_repositories(
            repositories(),
            &mapping,
            &edges,
            Some(&imported),
            &LabelOnlyRepositories::default(),
            Path::new("."),
            &mut materialize_repository_inputs,
        );
        assert_eq!(query.len(), 12);
        // Definitions retain declared module dependencies. Unresolved readers retain the
        // former generated inventory through separate fallback nodes.
        assert_eq!(
            inputs_of(&query, "//external:rules_go"),
            ["//external:rules_rs"]
        );
        assert!(inputs_of(&query, "//external:rules_rs").is_empty());
        assert_eq!(
            inputs_of(&query, "//external:!unresolved-module-rules_go+!rules_go"),
            [
                "//external:!unresolved-module-rules_rs+!rules_rs",
                "//external:rules_go++go_sdk+go_default_sdk",
                "//external:rules_go++go_sdk+go_toolchains",
            ]
        );
        assert_eq!(
            inputs_of(&query, "//external:!unresolved-module-rules_rs+!rules_rs"),
            [
                "//external:bd_crates",
                "//external:rules_rs++_crate+++isolated_crates+crate_repo",
                "//external:rules_rs++crate+bd_crates__anyhow-1.0.104",
            ]
        );
        // A repository definition is independent of its hidden-sibling fallback.
        assert!(inputs_of(&query, "//external:bd_crates").is_empty());
        assert_eq!(
            inputs_of(
                &query,
                "//external:!unresolved-import-rules_rs++crate+bd_crates!bd_crates"
            ),
            ["//external:rules_rs++crate+bd_crates__anyhow-1.0.104"]
        );
        assert_eq!(
            inputs_of(&query, "//external:!unresolved-import-rules_go++go_sdk+go_toolchains!rules_go++go_sdk+go_toolchains"),
            ["//external:rules_go++go_sdk+go_default_sdk"]
        );
        // Spokes stay leaves, and the root's own extension has no module node to hang off.
        assert!(inputs_of(&query, "//external:rules_go++go_sdk+go_default_sdk").is_empty());
        assert!(inputs_of(
            &query,
            "//external:rules_rs++crate+bd_crates__anyhow-1.0.104"
        )
        .is_empty());
        assert!(inputs_of(&query, "//external:+local+root_ext_repo").is_empty());

        // A label-only extension leaves the owner fallback, while other usages stay,
        // including an isolated usage of the same extension (#603).
        let label_only = lower_repositories(
            repositories(),
            &mapping,
            &edges,
            Some(&imported),
            &LabelOnlyRepositories {
                extensions: BTreeSet::from([
                    "rules_go++go_sdk".to_owned(),
                    "rules_rs++crate".to_owned(),
                ]),
                ..Default::default()
            },
            Path::new("."),
            &mut materialize_repository_inputs,
        );
        assert_eq!(label_only.len(), 12);
        assert_eq!(
            inputs_of(&label_only, "//external:rules_go"),
            ["//external:rules_rs"]
        );
        assert!(inputs_of(&label_only, "//external:rules_rs").is_empty());
        assert_eq!(
            inputs_of(
                &label_only,
                "//external:!unresolved-module-rules_go+!rules_go"
            ),
            ["//external:!unresolved-module-rules_rs+!rules_rs"]
        );
        assert_eq!(
            inputs_of(
                &label_only,
                "//external:!unresolved-module-rules_rs+!rules_rs"
            ),
            ["//external:rules_rs++_crate+++isolated_crates+crate_repo"]
        );
        assert_eq!(
            inputs_of(
                &label_only,
                "//external:!unresolved-import-rules_rs++crate+bd_crates!bd_crates"
            ),
            ["//external:rules_rs++crate+bd_crates__anyhow-1.0.104"]
        );
        assert_eq!(
            inputs_of(&label_only, "//external:!unresolved-import-rules_go++go_sdk+go_toolchains!rules_go++go_sdk+go_toolchains"),
            ["//external:rules_go++go_sdk+go_default_sdk"]
        );

        let cquery = lower_repositories(
            repositories(),
            &mapping,
            &edges,
            None,
            &LabelOnlyRepositories::default(),
            Path::new("."),
            &mut materialize_repository_inputs,
        );
        assert_eq!(cquery.len(), 8);
        assert_eq!(
            inputs_of(&cquery, "//external:rules_go"),
            ["//external:rules_rs"]
        );
        assert!(inputs_of(&cquery, "//external:rules_rs").is_empty());
        assert!(inputs_of(&cquery, "//external:bd_crates").is_empty());
        assert!(inputs_of(&cquery, "//external:rules_go++go_sdk+go_toolchains").is_empty());
    }

    #[test]
    fn label_only_extensions_resolve_to_unambiguous_usage_prefixes() {
        let mapping = parse_repo_mapping(
            r#"{"":"","rules_rs":"rules_rs+","rs":"rules_rs+","rules_go":"rules_go+"}"#,
        );
        let generated = [
            "rules_rs++crate+crates",
            "rules_go++go_sdk+go_toolchains",
            // Two `.bzl` files of rules_go export `pip`; Bazel names the second usage `pip2`.
            "rules_go++pip+pypi",
            "rules_go++pip2+pypi",
        ]
        .map(str::to_owned)
        .into();
        let mut options = probe_options(Path::new("."), PathBuf::from("unused"));
        options.label_only_module_extensions = [
            "@rules_rs//rs:extensions.bzl%crate",
            "@rs//rs:extensions.bzl%crate",
            "@@rules_go+//go:extensions.bzl%go_sdk",
            "@rules_go//python:extensions.bzl%pip",
            "@rules_go//go:extensions.bzl%nogo",
            "@unknown//:extensions.bzl%crate",
            "rules_rs.bzl%crate",
            "@rules_rs//rs:extensions.bzl%",
        ]
        .map(str::to_owned)
        .into();
        assert_eq!(
            options.label_only_extension_prefixes(&mapping, &generated),
            BTreeSet::from(["rules_go++go_sdk".to_owned(), "rules_rs++crate".to_owned()])
        );
    }

    #[test]
    fn filtering_preserves_new_variants_for_small_and_large_supplements() {
        let primary = ["//p:a", "//p:b", "//p:c", "//p:d", "//p:e", "//p:f"].map(rule_target);
        for primary in [&primary[..1], &primary[..]] {
            let mut extra = vec![
                rule_target("//p:new"),
                rule_target("//p:a"),
                rule_target("//p:new"),
            ];
            retain_supplemental_targets(&mut extra, primary);
            assert_eq!(
                extra.iter().filter_map(target_name).collect::<Vec<_>>(),
                ["//p:new", "//p:new"]
            );
        }
    }

    #[test]
    fn supplement_extends_coverage_without_replacing_primary_or_deduplicating_new_names() {
        let member = "owner++_ext+++usage+hub";
        let scope = IsolatedRepoScope {
            anchor: "hub".into(),
            members: BTreeSet::from([member.to_owned()]),
            aliases: RepoMapping::from([("hub".to_owned(), member.to_owned())]),
            ..Default::default()
        };
        let rule = |name: &str, input: &str| {
            let mut target = rule_target(name);
            target
                .rule
                .as_option_mut()
                .unwrap()
                .rule_input
                .push(input.to_owned());
            target
        };
        let primary = [rule("//pkg:reader", "@hub//:new")];
        let mut coverage = ScopedCoverage::default();
        coverage.record(&scope, &primary);
        assert_eq!(
            coverage.missing,
            BTreeSet::from([format!("@@{member}//:new")])
        );
        let mut extra = vec![
            rule("//pkg:reader", "@hub//:discarded"),
            rule("@hub//:new", "@hub//:new"),
            rule("@hub//:new", "@hub//:still_missing"),
        ];
        retain_supplemental_targets(&mut extra, &primary);
        assert_eq!(extra.len(), 2);
        coverage.record(&scope, &extra);
        assert_eq!(
            coverage.missing,
            BTreeSet::from([format!("@@{member}//:still_missing")])
        );
        assert_eq!(coverage.direct_readers, [true, true, true]);
    }

    #[test]
    fn scoped_build_loads_union_duplicate_observations_before_deduplication() {
        let repo = "owner++_ext+++usage+hub";
        let scope = IsolatedRepoScope {
            anchor: "hub".into(),
            members: BTreeSet::from([repo.to_owned()]),
            aliases: RepoMapping::from([("hub".to_owned(), repo.to_owned())]),
            ..Default::default()
        };
        let canonical = format!("@@{repo}//:defs.bzl");
        let source = |name: &str, loads: &[&str]| Target {
            r#type: target::Discriminator::SourceFile,
            source_file: buffa::MessageField::some(SourceFile {
                name: name.to_owned(),
                subinclude: loads.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut records = [
            source("@hub//:BUILD.bazel", &[&canonical]),
            source("@hub//:BUILD.bazel", &[]),
        ];
        for _ in 0..2 {
            let mut loads = BTreeMap::new();
            scope.record_build_loads(&records[..1], &mut loads);
            scope.record_build_loads(&records[1..], &mut loads);
            scope.record_build_loads(&[source("//pkg:BUILD", &[&canonical])], &mut loads);
            let mut targets = vec![
                rule_target("//pkg:consumer"),
                source("@hub//:BUILD.bazel", &[]),
            ];
            let mut coverage = ScopedCoverage::default();
            coverage.record(&scope, &targets);
            assert!(scope
                .connect_external_readers(&loads, &mut targets, &coverage)
                .is_err());
            targets.push(source("@hub//:defs.bzl", &[]));
            coverage.record(&scope, &targets[coverage.direct_readers.len()..]);
            scope
                .connect_external_readers(&loads, &mut targets, &coverage)
                .unwrap();
            assert_eq!(
                targets[0].rule.as_option().unwrap().rule_input,
                ["//external:hub"]
            );
            assert_eq!(
                targets[1].source_file.as_option().unwrap().subinclude,
                std::slice::from_ref(&canonical)
            );
            records.reverse();
        }
    }

    #[test]
    fn typed_repository_inputs_exclude_string_dictionary_keys() {
        use crate::proto::blaze_query::attribute::Discriminator as Kind;
        let mut attr = Attribute {
            r#type: Kind::LabelDictUnary,
            ..Default::default()
        };
        attr.label_dict_unary_value.push(Default::default());
        let entry = &mut attr.label_dict_unary_value[0];
        entry.key = "//:string".into();
        entry.value = "//:label".into();
        assert_eq!(
            attribute_label_values(&attr).collect::<Vec<_>>(),
            ["//:label"]
        );
        // The stock main-repository scan still sees both strings.
        assert_eq!(
            attribute_main_repo_labels(&[attr]).collect::<BTreeSet<_>>(),
            ["//:string", "//:label"].into()
        );
    }

    #[test]
    fn label_list_dictionary_reads_both_wire_encodings() {
        // LABEL_LIST_DICT in mod show_repo uses StringListDictEntry (field 11).
        // The schema also has LabelListDictEntry (field 10), with the same shape.
        for field in [0x5a, 0x52] {
            let mut wire = b"\x0a\x04deps\x10\x0c".to_vec();
            wire.push(field);
            wire.extend_from_slice(b"\x12\x0a\x07//:text\x12\x07//:file\x68\x01");
            let attribute = Attribute::decode_from_slice(&wire).unwrap();
            assert_eq!(
                attribute_label_values(&attribute).collect::<Vec<_>>(),
                ["//:file"]
            );
        }
    }

    #[test]
    fn isolated_usage_requires_a_complete_unique_root_identity() {
        let hub = "owner++_ext+++usage+hub";
        let spoke = "owner++_ext+++usage+spoke";
        let config = "owner++_ext+++usage+registry";
        let path = "owner++_ext+++usage+path";
        let peer = "owner++ext+neighbor";
        let other = "owner++_ext+++second+tool";
        let survey = ExtensionRepositories {
            imported: [hub.to_owned(), peer.to_owned(), other.to_owned()].into(),
            generated: [hub, spoke, config, path, peer, other]
                .map(str::to_owned)
                .into(),
            ..Default::default()
        };
        let mut rows: Vec<_> = [hub, spoke, config, path, peer, other]
            .map(|canonical| Repository {
                canonical_name: Some(canonical.to_owned()),
                original_name: Some(canonical.rsplit_once('+').unwrap().1.to_owned()),
                repo_rule_bzl_label: Some("@@owner+//:rules.bzl".into()),
                repo_rule_name: Some(
                    if canonical == path {
                        "new_unknown_class"
                    } else {
                        "archive"
                    }
                    .into(),
                ),
                ..Default::default()
            })
            .into();
        rows[1].attribute.push(Attribute {
            name: "registry_config".into(),
            r#type: attribute::Discriminator::Label,
            string_value: Some(format!("@@{config}//:dl")),
            ..Default::default()
        });
        let mapping =
            serde_json::to_vec(&serde_json::json!({"renamed":hub,"peer":peer,"mod":"owner+"}))
                .unwrap();
        let requested = "@renamed";
        let resolve = |rows: &[Repository], survey: &ExtensionRepositories| {
            resolve_isolated_root(requested, &mapping, survey, rows)
        };
        let refuses = |result: Result<IsolatedRepoScope>, expected: &str| {
            let error = match result {
                Ok(_) => panic!("isolated root unexpectedly accepted"),
                Err(error) => format!("{error:#}"),
            };
            assert!(error.contains(expected), "{error}");
        };
        for _ in 0..2 {
            assert_eq!(
                resolve(&rows, &survey).unwrap().members,
                [hub, spoke, config, path].map(str::to_owned).into()
            );
            rows.reverse();
        }
        // A substituted anchor cannot qualify a different isolated or unisolated group.
        for substituted in [peer, "foreign++_ext+dep+1+usage+hub"] {
            let diverted =
                serde_json::to_vec(&serde_json::json!({"renamed":substituted,"mod":"owner+"}))
                    .unwrap();
            refuses(
                resolve_isolated_root(requested, &diverted, &survey, &rows),
                substituted,
            );
        }
        // Separate imported members prevent the hub from covering the whole usage.
        let mut split = survey.clone();
        split.imported.insert(spoke.into());
        refuses(
            resolve(&rows, &split),
            &format!("extra imported repository {spoke}"),
        );
        // A known outside repository-time read has no guaranteed ordinary target edge.
        let mut outside = rows.clone();
        outside[4].attribute = outside[1].attribute.clone();
        refuses(
            resolve(&outside, &survey),
            &format!("outside repository {peer} attribute registry_config reads @@{config}//:dl"),
        );
        // Same wire slot, different meaning. String list dictionaries do not
        // declare a repository input; lists of labels can read this usage.
        let mut dict = Attribute {
            name: "settings".into(),
            r#type: attribute::Discriminator::StringListDict,
            ..Default::default()
        };
        dict.string_list_dict_value.push(Default::default());
        dict.string_list_dict_value[0].key = "//:text".into();
        dict.string_list_dict_value[0].value = vec![format!("@@{config}//:dl")];
        outside[4].attribute = vec![dict];
        assert!(resolve(&outside, &survey).is_ok());
        outside[4].attribute[0].r#type = attribute::Discriminator::LabelListDict;
        refuses(
            resolve(&outside, &survey),
            &format!("outside repository {peer} attribute settings reads @@{config}//:dl"),
        );
        // A repository with an output label is outside the supported read contract.
        for kind in [
            attribute::Discriminator::Output,
            attribute::Discriminator::OutputList,
        ] {
            outside[4].attribute[0].r#type = kind;
            refuses(
                resolve(&outside, &survey),
                &format!("attribute settings has unsupported type {kind:?}"),
            );
        }
        let mut ambiguous = survey;
        ambiguous
            .imported
            .insert("foreign++_ext+++usage+hub".into());
        refuses(resolve(&rows, &ambiguous), "foreign++_ext+++usage+hub");
        ambiguous.imported.remove("foreign++_ext+++usage+hub");
        let mut missing = rows.clone();
        missing.retain(|row| row.canonical_name.as_deref() != Some(spoke));
        refuses(resolve(&missing, &ambiguous), spoke);
        let mut replaced = rows.clone();
        replaced[1].original_name = Some("different".into());
        refuses(resolve(&replaced, &ambiguous), "different");
        let malformed = "owner++_ext+++usage+";
        ambiguous.generated.insert(malformed.into());
        let mut empty_name = rows.clone();
        empty_name.push(Repository {
            canonical_name: Some(malformed.into()),
            original_name: Some(String::new()),
            repo_rule_bzl_label: Some("@@owner+//:rules.bzl".into()),
            repo_rule_name: Some("archive".into()),
            ..Default::default()
        });
        refuses(resolve(&empty_name, &ambiguous), malformed);
        ambiguous.generated.remove(malformed);
        rows[1].attribute[0].string_value = Some("@ambiguous".into());
        refuses(resolve(&rows, &ambiguous), "unresolved label @ambiguous");
        rows[1].attribute[0].r#type = attribute::Discriminator::Unknown;
        refuses(resolve(&rows, &ambiguous), "unsupported type UNKNOWN");
    }

    #[test]
    fn extension_repos_carry_their_owning_modules_definition() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(workspace.path().join("rules.patch"), "patch v1").unwrap();
        let mapping = parse_repo_mapping(
            r#"{"":"","rules_rs":"rules_rs+","rules_rust":"rules_rs++rules_rust+rules_rust"}"#,
        );
        let repositories = || {
            vec![
                Repository {
                    canonical_name: Some("rules_rs+".into()),
                    repo_rule_name: Some("http_archive".into()),
                    attribute: vec![Attribute {
                        name: "patches".into(),
                        r#type: attribute::Discriminator::LabelList,
                        string_list_value: vec!["//:rules.patch".into()],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                Repository {
                    canonical_name: Some("rules_rs++rules_rust+rules_rust".into()),
                    repo_rule_name: Some("_rules_rust_repo".into()),
                    ..Default::default()
                },
                Repository {
                    canonical_name: Some("rules_rs++crate+bd_crates__anyhow".into()),
                    repo_rule_name: Some("crate_repo".into()),
                    ..Default::default()
                },
                Repository {
                    canonical_name: Some("rules_rs++_crate+++isolated_crates+crate_repo".into()),
                    repo_rule_name: Some("crate_repo".into()),
                    ..Default::default()
                },
                Repository {
                    canonical_name: Some("+local+root_repo".into()),
                    ..Default::default()
                },
            ]
        };
        let module_hash = |targets: &[Target], name: &str| {
            targets
                .iter()
                .find(|target| target_name(target) == Some(name))
                .unwrap_or_else(|| panic!("{name} missing"))
                .rule
                .as_option()
                .unwrap()
                .attribute
                .iter()
                .find(|attribute| attribute.name == "_bazel_diff_module_hash")
                .and_then(|attribute| attribute.string_value.clone())
        };
        let lower = || {
            lower_repositories(
                repositories(),
                &mapping,
                &BTreeMap::new(),
                None,
                &LabelOnlyRepositories::default(),
                workspace.path(),
                &mut materialize_repository_inputs,
            )
        };

        let before = lower();
        let hub = module_hash(&before, "//external:rules_rust").unwrap();
        // Every repository of the module's extensions carries the same digest of the module.
        for name in [
            "//external:rules_rs++crate+bd_crates__anyhow",
            "//external:rules_rs++_crate+++isolated_crates+crate_repo",
        ] {
            assert_eq!(module_hash(&before, name), Some(hub.clone()));
        }
        // The module itself and the root's own extension repos carry none.
        assert!(module_hash(&before, "//external:rules_rs").is_none());
        assert!(module_hash(&before, "//external:+local+root_repo").is_none());

        // Editing the module's override patch changes its extension repositories too (the
        // #522 case for a module consumed only through its extensions), in either mode.
        fs::write(workspace.path().join("rules.patch"), "patch v2").unwrap();
        let after = lower();
        assert_ne!(module_hash(&after, "//external:rules_rust").unwrap(), hub);

        // The digest ignores a mirror move of a pinned download, like the hasher does.
        let paths = RepositoryWorkspace::new(workspace.path());
        let pinned = |urls: &str| Repository {
            repo_rule_name: Some("http_archive".into()),
            attribute: vec![
                Attribute {
                    name: "urls".into(),
                    r#type: attribute::Discriminator::StringList,
                    string_list_value: vec![urls.into()],
                    ..Default::default()
                },
                Attribute {
                    name: "integrity".into(),
                    r#type: attribute::Discriminator::String,
                    string_value: Some("sha256-abc".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            prepared_definition_hash(&pinned("https://a/x.zip"), &paths),
            prepared_definition_hash(&pinned("https://b/x.zip"), &paths)
        );
        let mut unpinned = pinned("https://a/x.zip");
        unpinned.attribute.pop();
        let mut moved = pinned("https://b/x.zip");
        moved.attribute.pop();
        assert_ne!(
            prepared_definition_hash(&unpinned, &paths),
            prepared_definition_hash(&moved, &paths)
        );

        // The digest also ignores the checkout path in a `file://%workspace%` registry's patch
        // URLs, which their integrity pins; a changed integrity still changes it.
        let patched = |root: &str, integrity: &str| Repository {
            repo_rule_name: Some("http_archive".into()),
            attribute: vec![Attribute {
                name: "remote_patches".into(),
                r#type: attribute::Discriminator::StringDict,
                string_dict_value: vec![crate::proto::blaze_query::StringDictEntry {
                    key: format!("file://{root}/registry/patches/fix.patch"),
                    value: integrity.into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            prepared_definition_hash(&patched("/one", "sha256-p"), &paths),
            prepared_definition_hash(&patched("/two", "sha256-p"), &paths)
        );
        assert_ne!(
            prepared_definition_hash(&patched("/one", "sha256-p"), &paths),
            prepared_definition_hash(&patched("/one", "sha256-q"), &paths)
        );
    }

    /// Fake Bazel for the extension-repository flow: a root that imports `rules_go` and a
    /// `pypi` hub, `rules_go` importing `go_toolchains`, and two repositories per extension
    /// that nobody imports. `show_repo` answers with the pre-encoded `repositories`, and
    /// `query` with `//app:lib`.
    #[cfg(unix)]
    fn extension_flow_script(
        workspace: &Path,
        repositories: &[Repository],
        failing_representative: Option<&str>,
    ) -> PathBuf {
        let repo_proto = workspace.join("show-repo.pb");
        write_delimited(&repo_proto, repositories);
        let query_proto = workspace.join("query-result.pb");
        write_delimited(&query_proto, &[rule_target("//app:lib")]);
        let calls = workspace.join("calls.log");
        let script = workspace.join("fake-bazel.sh");
        let fail = failing_representative.unwrap_or("never-matches");
        let body = format!(
            r#"#!/bin/sh
args="$*"
echo "$args" >> "{calls}"
if [ "$1 $2" = "info output_base" ]; then
  pwd
  exit 0
fi
if echo "$args" | grep -q "mod graph --output=json"; then
  if [ -f omit-graph-hint ]; then
    echo '{{"key":"<root>","name":"root","dependencies":[{{"key":"rules_go@0.62.0","name":"rules_go","dependencies":[]}}]}}'
  else
    echo '{{"key":"<root>","name":"root","dependencies":[{{"key":"rules_go@0.62.0","name":"rules_go","dependencies":[]}},{{"key":"rules_python@1.8.4","name":"rules_python","dependencies":[]}}]}}'
  fi
  exit 0
fi
if echo "$args" | grep -q "mod graph"; then
  echo "root"
  exit 0
fi
if echo "$args" | grep -q "version"; then
  echo "Build label: 8.7.0"
  exit 0
fi
if [ "$2" = "dump_repo_mapping" ]; then
  shift 2
  if [ -z "$1" ]; then
    echo '{{"":"","rules_go":"rules_go+","rules_python":"rules_python+","pypi":"rules_python++pip+pypi","bazel_tools":"bazel_tools"}}'
    shift
    if [ "$#" -eq 0 ] || [ -f truncated-survey ]; then exit 0; fi
    if [ -f unavailable-survey ]; then exit 2; fi
  fi
  for repo in "$@"; do
    if [ "$repo" = "unknown_hidden+" ]; then echo "Unknown module repository" >&2; exit 2; fi
    if [ "$repo" = "{fail}" ]; then
      echo "ERROR: extension evaluation failed for $repo" >&2
      exit 2
    fi
    case "$repo" in
      rules_go+) echo '{{"go_toolchains":"rules_go++go_sdk+go_toolchains","bazel_tools":"bazel_tools","rules_go":"rules_go+"}}' ;;
      rules_python+) echo '{{"pypi":"rules_python++pip+pypi","rules_python":"rules_python+"}}' ;;
      rules_go++go_sdk+*) echo '{{"go_toolchains":"rules_go++go_sdk+go_toolchains","go_default_sdk":"rules_go++go_sdk+go_default_sdk","rules_go":"rules_go+"}}' ;;
      rules_python++pip+*) echo '{{"pypi":"rules_python++pip+pypi","pypi_312_six":"rules_python++pip+pypi_312_six","rules_python":"rules_python+"}}' ;;
      *) echo '{{"rules_go":"rules_go+","pypi":"rules_python++pip+pypi","rules_python":"rules_python+"}}' ;;
    esac
  done
  exit 0
fi
if echo "$args" | grep -q "mod show_repo"; then
  cat "{repos}"
  exit 0
fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output_file" ]; then
    cp "{query}" "$2"
    exit 0
  fi
  shift
done
exit 1
"#,
            calls = calls.display(),
            repos = repo_proto.display(),
            query = query_proto.display(),
        );
        fs::write(&script, body).unwrap();
        script
    }

    #[test]
    #[cfg(unix)]
    fn query_bzlmod_repos_enumerates_extension_repositories() {
        let workspace = tempfile::tempdir().unwrap();
        let repositories = [
            "rules_go+",
            "rules_python+",
            "rules_python++pip+pypi",
            "rules_python++pip+pypi_312_six",
            "rules_go++go_sdk+go_toolchains",
            "rules_go++go_sdk+go_default_sdk",
        ]
        .into_iter()
        .map(|canonical| Repository {
            canonical_name: Some(canonical.into()),
            repo_rule_name: Some("http_archive".into()),
            ..Default::default()
        })
        .collect::<Vec<_>>();
        let script = extension_flow_script(workspace.path(), &repositories, None);
        let options = BazelOptions {
            workspace: workspace.path().to_path_buf(),
            bazel: PathBuf::from("/bin/sh"),
            startup_options: vec![script.to_str().unwrap().to_owned()],
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: false,
            cquery_expression: None,
            keep_going: false,
            fine_grained_external_repos: BTreeSet::new(),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: true,
            exclude_targets_query: None,
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        };

        // A legacy //external rule can have the same name as a synthetic repository.
        let overlapping = "//external:rules_python++pip+pypi_312_six";
        write_delimited(
            &workspace.path().join("query-result.pb"),
            &[rule_target("//app:lib"), rule_target(overlapping)],
        );
        let targets = options.query_all_targets().unwrap();
        let names = targets
            .iter()
            .filter_map(target_name)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from([
                "//app:lib",
                "//external:!unresolved-import-rules_go++go_sdk+go_toolchains!rules_go++go_sdk+go_toolchains",
                "//external:!unresolved-import-rules_python++pip+pypi!pypi",
                "//external:!unresolved-module-rules_go+!rules_go",
                "//external:!unresolved-module-rules_python+!rules_python",
                "//external:pypi",
                "//external:rules_go",
                "//external:rules_go++go_sdk+go_default_sdk",
                "//external:rules_go++go_sdk+go_toolchains",
                "//external:rules_python",
                "//external:rules_python++pip+pypi_312_six",
            ])
        );
        let inputs_of = |name: &str| {
            targets
                .iter()
                .find(|target| target_name(target) == Some(name))
                .unwrap()
                .rule
                .as_option()
                .unwrap()
                .rule_input
                .clone()
        };
        assert!(inputs_of("//external:rules_go").is_empty());
        assert!(inputs_of("//external:rules_python").is_empty());
        assert_eq!(
            inputs_of("//external:!unresolved-module-rules_go+!rules_go"),
            [
                "//external:rules_go++go_sdk+go_default_sdk",
                "//external:rules_go++go_sdk+go_toolchains",
            ]
        );
        assert_eq!(
            inputs_of("//external:!unresolved-module-rules_python+!rules_python"),
            [
                "//external:pypi",
                "//external:rules_python++pip+pypi_312_six",
            ]
        );
        assert!(inputs_of("//external:pypi").is_empty());
        assert!(inputs_of("//external:rules_go++go_sdk+go_toolchains").is_empty());
        assert_eq!(
            inputs_of("//external:!unresolved-import-rules_python++pip+pypi!pypi"),
            ["//external:rules_python++pip+pypi_312_six"]
        );
        assert_eq!(
            inputs_of("//external:!unresolved-import-rules_go++go_sdk+go_toolchains!rules_go++go_sdk+go_toolchains"),
            ["//external:rules_go++go_sdk+go_default_sdk"]
        );

        // Every generated repository was asked of `show_repo`, in one invocation, and the
        // mapping rounds were one over the modules and one over a representative per extension.
        let calls = fs::read_to_string(workspace.path().join("calls.log")).unwrap();
        let show_repo = calls
            .lines()
            .filter(|line| line.contains("mod show_repo"))
            .collect::<Vec<_>>();
        assert_eq!(show_repo.len(), 1, "{calls}");
        for repo in [
            "@@rules_go++go_sdk+go_default_sdk",
            "@@rules_python++pip+pypi_312_six",
            "@@rules_python++pip+pypi",
            "@@rules_go+",
        ] {
            assert!(show_repo[0].contains(repo), "{}", show_repo[0]);
        }
        let dumps = calls
            .lines()
            .filter(|line| line.contains("mod dump_repo_mapping"))
            .collect::<Vec<_>>();
        // The successful root probe is reused before the dependent module and
        // representative mapping rounds.
        assert_eq!(dumps.len(), 3, "{calls}");
        assert!(
            dumps[1].ends_with("mod dump_repo_mapping rules_go+ rules_python+"),
            "{calls}"
        );
        assert!(
            dumps[2].ends_with(
                "mod dump_repo_mapping rules_go++go_sdk+go_toolchains rules_python++pip+pypi"
            ),
            "{calls}"
        );

        // Definition hashing must use the same rule that deduplication keeps.
        let options = crate::hash::HashOptions {
            bazel: options,
            content_hashes: None,
            ignored_attributes: HashSet::new(),
            seed_filepaths: BTreeSet::new(),
            modified_filepaths: BTreeSet::new(),
            track_deps: true,
            always_affected_tags: HashSet::new(),
            partial_tree: None,
        };
        let raw = crate::hash::hash_targets(&options, targets).unwrap();
        let streamed = crate::hash::generate_hashes(&options).unwrap();
        assert_eq!(raw.hashes[overlapping], streamed.hashes[overlapping]);
    }

    #[test]
    #[cfg(unix)]
    fn module_survey_preserves_ordered_targets_and_falls_back_on_incomplete_answers() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path();
        let repo = Repository {
            canonical_name: Some("rules_go++go_sdk+go_default_sdk".into()),
            repo_rule_name: Some("http_archive".into()),
            ..Default::default()
        };
        let options = probe_options(path, extension_flow_script(path, &[repo], None));
        let original = options
            .query_all_targets_with(materialize_repository_inputs_for_batch, None)
            .unwrap();
        fs::write(path.join("MODULE.bazel"), "").unwrap();
        for (marker, expected_dumps) in [
            (None, 2),
            (Some("truncated-survey"), 4),
            (Some("unavailable-survey"), 4),
        ] {
            if let Some(name) = marker {
                fs::write(path.join(name), "").unwrap();
            }
            fs::write(path.join("calls.log"), "").unwrap();
            let queried = options
                .query_all_targets_with(materialize_repository_inputs_for_batch, None)
                .unwrap();
            assert_eq!(queried.targets, original.targets);
            assert_eq!(queried.root_mapping, original.root_mapping);
            assert_eq!(queried.module_graph_json, original.module_graph_json);
            let calls = fs::read_to_string(path.join("calls.log")).unwrap();
            let dumps = calls
                .lines()
                .filter(|line| line.contains("mod dump_repo_mapping"))
                .collect::<Vec<_>>();
            assert_eq!(dumps.len(), expected_dumps, "{calls}");
            assert!(
                dumps[0].ends_with("mod dump_repo_mapping  rules_go+ rules_python+"),
                "{calls}"
            );
            assert_eq!(
                calls
                    .lines()
                    .filter(|line| line.contains("mod graph --output=json"))
                    .count(),
                1,
                "{calls}"
            );
            if let Some(name) = marker {
                fs::remove_file(path.join(name)).unwrap();
            }
        }

        // The root mapping, not the graph hint, decides which modules must be read.
        fs::remove_file(path.join("MODULE.bazel")).unwrap();
        fs::write(path.join("omit-graph-hint"), "").unwrap();
        let original = options
            .query_all_targets_with(materialize_repository_inputs_for_batch, None)
            .unwrap();
        fs::write(path.join("MODULE.bazel"), "").unwrap();
        fs::write(path.join("calls.log"), "").unwrap();
        let queried = options
            .query_all_targets_with(materialize_repository_inputs_for_batch, None)
            .unwrap();
        assert_eq!(queried.targets, original.targets);
        assert_eq!(queried.root_mapping, original.root_mapping);
        assert_eq!(queried.module_graph_json, original.module_graph_json);
        let calls = fs::read_to_string(path.join("calls.log")).unwrap();
        let dumps = calls
            .lines()
            .filter(|line| line.contains("mod dump_repo_mapping"))
            .collect::<Vec<_>>();
        assert_eq!(dumps.len(), 3, "{calls}");
        assert!(
            dumps[0].ends_with("mod dump_repo_mapping  rules_go+"),
            "{calls}"
        );
        assert!(
            dumps[1].ends_with("mod dump_repo_mapping rules_python+"),
            "{calls}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn extension_repository_enumeration_skips_broken_extensions_only_with_keep_going() {
        let workspace = tempfile::tempdir().unwrap();
        let repositories = ["rules_go+", "rules_python+", "rules_python++pip+pypi"]
            .into_iter()
            .map(|canonical| Repository {
                canonical_name: Some(canonical.into()),
                repo_rule_name: Some("http_archive".into()),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let script = extension_flow_script(
            workspace.path(),
            &repositories,
            Some("rules_go++go_sdk+go_toolchains"),
        );
        let mut options = BazelOptions {
            workspace: workspace.path().to_path_buf(),
            bazel: PathBuf::from("/bin/sh"),
            startup_options: vec![script.to_str().unwrap().to_owned()],
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: false,
            cquery_expression: None,
            keep_going: false,
            fine_grained_external_repos: BTreeSet::new(),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: true,
            exclude_targets_query: None,
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        };
        let error = options.query_all_targets().unwrap_err().to_string();
        assert!(error.contains("extension evaluation failed"), "{error}");

        // With --keep_going the broken extension is skipped and the healthy one still enumerated.
        options.keep_going = true;
        let targets = options.query_all_targets().unwrap();
        let names = targets
            .iter()
            .filter_map(target_name)
            .collect::<BTreeSet<_>>();
        assert!(names.contains("//external:pypi"), "{names:?}");
        assert!(names.contains("//external:rules_go"), "{names:?}");
        let calls = fs::read_to_string(workspace.path().join("calls.log")).unwrap();
        let show_repo = calls
            .lines()
            .rev()
            .find(|line| line.contains("mod show_repo"))
            .unwrap();
        assert!(
            show_repo.contains("@@rules_python++pip+pypi"),
            "{show_repo}"
        );
        assert!(!show_repo.contains("go_default_sdk"), "{show_repo}");

        // Recovery can lose a hidden module without a failed extension. Keep the
        // global owner on that survey, even if the visible module read succeeded.
        let visible = BTreeMap::from([("rules_python+".into(), vec!["rules_python".into()])]);
        let mut failed = FailedExtensions::default();
        let resolved = |hidden, failed: &mut FailedExtensions| {
            options
                .extension_repositories(&visible, hidden, BTreeMap::new(), true, failed)
                .unwrap()
        };
        assert!(resolved(Vec::new(), &mut failed).complete_mappings);
        let recovered = resolved(vec!["unknown_hidden+".into()], &mut failed);
        assert!(!recovered.complete_mappings);
        assert!(failed.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn dependency_fingerprint_fallback_chain_covers_streamed_and_text_paths() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(
            workspace.path().join("MODULE.bazel"),
            "module(name = \"test\")\n",
        )
        .unwrap();

        let selected_repos_marker = workspace.path().join("selected-repos-called");
        let script = workspace.path().join("fake-bazel.sh");
        let body = format!(
            r#"#!/bin/sh
args="$*"
if echo "$args" | grep -q "mod graph --output=json"; then
  printf '{{"modules":["m"]}}\n'
  exit 0
fi
if echo "$args" | grep -q "mod graph"; then
  echo "root"
  exit 0
fi
if echo "$args" | grep -q "mod dump_repo_mapping"; then
  echo '{{"pip":"rules_python+0.31.0","local":"local~override","main":"main"}}'
  exit 0
fi
if echo "$args" | grep -q "mod show_repo" && echo "$args" | grep -q -- "--output=streamed_proto"; then
  exit 2
fi
if echo "$args" | grep -q "mod show_repo" && echo "$args" | grep -q -- "--all_visible_repos" && echo "$args" | grep -q -- "--output=text"; then
  exit 3
fi
if echo "$args" | grep -q "mod show_repo" && echo "$args" | grep -q -- "--output=text"; then
  : > "{}"
  echo "selected-repos-text"
  exit 0
fi
exit 1
"#,
            selected_repos_marker.display(),
        );
        fs::write(&script, body).unwrap();

        let options = BazelOptions {
            workspace: workspace.path().to_path_buf(),
            bazel: PathBuf::from("/bin/sh"),
            startup_options: vec![script.to_str().unwrap().to_owned()],
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: false,
            cquery_expression: None,
            keep_going: false,
            fine_grained_external_repos: BTreeSet::new(),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: false,
            exclude_targets_query: None,
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        };

        let fingerprint = options.dependency_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit()));
        assert!(selected_repos_marker.is_file());
    }

    #[test]
    #[cfg(unix)]
    fn guarded_cache_distinguishes_toolchain_metadata_from_the_same_release() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path();
        let script = root.join("bazel.sh");
        fs::write(
            &script,
            r#"case "$1 $2" in
"mod dump_repo_mapping") echo '{}' ;;
"mod graph")
  case "$*" in
    *--include_toolchain_registrations*) cat registrations ;;
    *) echo '{"key":"<root>","dependencies":[]}' ;;
  esac ;;
"query set()") test -f typed ;;
"mod show_repo") exit 0 ;;
*) exit 1 ;;
esac
"#,
        )
        .unwrap();
        let options = probe_options(root, script);
        let fingerprint = || options.dependency_fingerprint().unwrap();
        let ordinary = fingerprint();
        fs::write(
            root.join("registrations"),
            r#"{"key":"<root>","dependencies":[],"moduleToolchainRegistrations":[]}"#,
        )
        .unwrap();
        let registered = fingerprint();
        assert_ne!(registered, ordinary);
        fs::write(root.join("typed"), "").unwrap();
        let typed = fingerprint();
        assert_ne!(typed, registered);
        assert_eq!(typed, fingerprint());
    }

    #[test]
    #[cfg(unix)]
    fn query_bzlmod_repos_honors_keep_going() {
        let workspace = tempfile::tempdir().unwrap();
        let query_proto = workspace.path().join("query-result.pb");
        write_delimited(&query_proto, &[rule_target("//app:lib")]);

        // Fake Bazel where `mod graph` succeeds (`is_bzlmod_enabled()` is true),
        // `version` returns 8.6.1, `mod dump_repo_mapping` returns an external repo,
        // `mod show_repo` fails, and `query` writes `//app:lib` to `--output_file`.
        let show_repo_fail_script = workspace.path().join("fake-bazel-show-repo-fail.sh");
        let body = format!(
            r#"#!/bin/sh
args="$*"
if echo "$args" | grep -q "mod graph"; then
  echo "root"
  exit 0
fi
if echo "$args" | grep -q "version"; then
  echo "Build label: 8.6.1"
  exit 0
fi
if echo "$args" | grep -q "mod dump_repo_mapping"; then
  echo '{{"pip":"rules_python+0.31.0"}}'
  exit 0
fi
if echo "$args" | grep -q "mod show_repo"; then
  echo "transient fetch failure" >&2
  exit 2
fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output_file" ]; then
    cp "{}" "$2"
    exit 0
  fi
  shift
done
exit 1
"#,
            query_proto.display(),
        );
        fs::write(&show_repo_fail_script, body).unwrap();

        let mut options = BazelOptions {
            workspace: workspace.path().to_path_buf(),
            bazel: PathBuf::from("/bin/sh"),
            startup_options: vec![show_repo_fail_script.to_str().unwrap().to_owned()],
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: false,
            cquery_expression: None,
            keep_going: false,
            fine_grained_external_repos: BTreeSet::new(),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: true,
            exclude_targets_query: None,
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        };

        let show_repo_err = options.query_all_targets().unwrap_err();
        assert!(show_repo_err
            .to_string()
            .contains("bazel mod show_repo failed"));

        // With `keep_going = true`, `query_all_targets` logs a warning and falls back to main targets.
        options.keep_going = true;
        let targets = options.query_all_targets().unwrap();
        assert_eq!(
            targets.iter().filter_map(target_name).collect::<Vec<_>>(),
            ["//app:lib"]
        );
    }

    #[test]
    fn extension_failure_reads_both_bazel_wordings() {
        let not_generated = "ERROR: module extension @@transitive_dep+//:extensions.bzl%broken does not generate repository \"missing_repo\", yet it is imported as \"missing_repo\" in the usage at @@transitive_dep+//:MODULE.bazel:10:23\nERROR: Results may be incomplete as 1 extension failed.\n";
        let failure = extension_failure(not_generated).unwrap();
        assert_eq!(
            failure.extensions,
            BTreeSet::from(["@@transitive_dep+//:extensions.bzl%broken".to_owned()])
        );
        assert!(failure.answered);

        let evaluation = "ERROR: /cache/external/rules_swift+/swift/extensions.bzl:19:9: Traceback (most recent call last):\n\tFile \"/cache/external/rules_swift+/swift/extensions.bzl\", line 19, column 9, in _impl\n\t\tfail(\"boom\")\nError in fail: boom\nERROR: error evaluating module extension @@rules_swift+//swift:extensions.bzl%non_module_deps\n";
        let failure = extension_failure(evaluation).unwrap();
        assert_eq!(
            failure.extensions,
            BTreeSet::from(["@@rules_swift+//swift:extensions.bzl%non_module_deps".to_owned()])
        );
        assert!(!failure.answered);

        assert!(extension_failure("ERROR: Bzlmod has to be enabled\n").is_none());
        assert!(extension_failure("ERROR: Unknown command 'dump_repo_mapping'\n").is_none());
    }

    #[cfg(unix)]
    fn probe_options(workspace: &Path, script: PathBuf) -> BazelOptions {
        BazelOptions {
            workspace: workspace.to_path_buf(),
            bazel: PathBuf::from("/bin/sh"),
            startup_options: vec![script.to_str().unwrap().to_owned()],
            command_options: Vec::new(),
            cquery_options: Vec::new(),
            use_cquery: false,
            cquery_expression: None,
            keep_going: false,
            fine_grained_external_repos: BTreeSet::new(),
            label_only_module_extensions: BTreeSet::new(),
            isolated_dependency_root: None,
            exclude_external_targets: true,
            exclude_targets_query: None,
            no_bazelrc: false,
            verbose: false,
            cancellation: None,
        }
    }

    /// `is_bzlmod_enabled()` is decided by `dump_repo_mapping ""`, which a failed module
    /// extension in the graph does not touch; `mod graph`, which does, is the fallback for a
    /// Bazel without `dump_repo_mapping` and counts even when it only answered partially.
    #[test]
    #[cfg(unix)]
    fn bzlmod_probe_survives_a_failed_extension_and_an_old_bazel() {
        let workspace = tempfile::tempdir().unwrap();
        let script = |name: &str, dump: &str, graph: &str| {
            let path = workspace.path().join(name);
            fs::write(
                &path,
                format!(
                    "#!/bin/sh\nif [ \"$2\" = dump_repo_mapping ]; then\n{dump}\nfi\nif [ \"$2\" = graph ]; then\n{graph}\nfi\nexit 1\n"
                ),
            )
            .unwrap();
            path
        };
        let marker = "echo 'ERROR: error evaluating module extension @@dep+//:ext.bzl%broken' >&2; echo 'ERROR: Results may be incomplete as 1 extension failed.' >&2; exit 2";

        let mapping_answers_graph_fails = script(
            "probe-a.sh",
            "echo '{\"\":\"\",\"dep\":\"dep+\"}'; exit 0",
            marker,
        );
        assert!(probe_options(workspace.path(), mapping_answers_graph_fails).is_bzlmod_enabled());

        let no_dump_repo_mapping = script(
            "probe-b.sh",
            "echo \"ERROR: Unknown command 'dump_repo_mapping'\" >&2; exit 2",
            "echo '<root>'; exit 0",
        );
        assert!(probe_options(workspace.path(), no_dump_repo_mapping).is_bzlmod_enabled());

        let no_dump_repo_mapping_graph_partial = script("probe-c.sh", "exit 2", marker);
        assert!(
            probe_options(workspace.path(), no_dump_repo_mapping_graph_partial).is_bzlmod_enabled()
        );

        let bzlmod_disabled = script(
            "probe-d.sh",
            "echo 'ERROR: Bzlmod has to be enabled for mod command to work.' >&2; exit 2",
            "echo 'ERROR: Bzlmod has to be enabled for mod command to work.' >&2; exit 2",
        );
        assert!(!probe_options(workspace.path(), bzlmod_disabled).is_bzlmod_enabled());
    }

    /// Fake Bazel for a workspace whose transitive module `transitive_dep` imports
    /// `missing_repo` from an extension that does not generate it (#531), answering the way
    /// Bazel 8.7 and 9.3 do: `mod graph`, `dump_repo_mapping <module>` and `show_repo` print
    /// everything that does not need the extension, report it on stderr and exit 2; asking
    /// for one of the extension's repositories by name prints nothing and exits 37 (or 2 for
    /// `show_repo`) without the `Results may be incomplete` line.
    #[cfg(unix)]
    fn failed_extension_script(workspace: &Path, query_targets: &[Target]) -> PathBuf {
        fs::write(workspace.join("MODULE.bazel"), "").unwrap();
        let repo_proto = workspace.join("show-repo.pb");
        write_delimited(
            &repo_proto,
            &["direct_dep+", "transitive_dep+"]
                .into_iter()
                .map(|canonical| Repository {
                    canonical_name: Some(canonical.into()),
                    repo_rule_name: Some("local_repository".into()),
                    ..Default::default()
                })
                .collect::<Vec<_>>(),
        );
        let query_proto = workspace.join("query-result.pb");
        write_delimited(&query_proto, query_targets);
        let calls = workspace.join("calls.log");
        let script = workspace.join("fake-bazel.sh");
        let body = format!(
            r#"#!/bin/sh
args="$*"
echo "$args" >> "{calls}"
err='ERROR: module extension @@transitive_dep+//:extensions.bzl%broken does not generate repository "missing_repo", yet it is imported as "missing_repo" in the usage at @@transitive_dep+//:MODULE.bazel:10:23'
marker='ERROR: Results may be incomplete as 1 extension failed.'
if echo "$args" | grep -q "mod graph --output=json"; then
  echo '{{"key":"<root>","name":"root","dependencies":[{{"key":"direct_dep@_","name":"direct_dep","dependencies":[{{"key":"transitive_dep@_","name":"transitive_dep","dependencies":[]}}]}},{{"key":"transitive_dep@_","name":"transitive_dep","dependencies":[]}}]}}'
  echo "$err" >&2; echo "$marker" >&2; exit 2
fi
if echo "$args" | grep -q "mod graph"; then
  echo "<root>"; echo "$err" >&2; echo "$marker" >&2; exit 2
fi
if echo "$args" | grep -q "version"; then
  echo "Build label: 8.7.0"
  exit 0
fi
if [ "$2" = "dump_repo_mapping" ] && [ -z "$3" ]; then
  echo '{{"":"","direct_dep":"direct_dep+","transitive_dep":"transitive_dep+","missing_repo":"transitive_dep++broken+missing_repo","bazel_tools":"bazel_tools"}}'
  exit 0
fi
if echo "$args" | grep -q "mod show_repo" && echo "$args" | grep -q "transitive_dep++broken+"; then
  echo "$err" >&2; echo "$err. Type 'bazel help mod' for syntax and help." >&2; exit 2
fi
if echo "$args" | grep -q "transitive_dep++broken+"; then
  echo "$err" >&2; exit 37
fi
if echo "$args" | grep -q "mod dump_repo_mapping"; then
  for repo in $(echo "$args" | sed 's/.*dump_repo_mapping//'); do
    case "$repo" in
      direct_dep+) echo '{{"direct_dep":"direct_dep+","transitive_dep":"transitive_dep+","bazel_tools":"bazel_tools"}}' ;;
      transitive_dep+) echo '{{"missing_repo":"transitive_dep++broken+missing_repo","transitive_dep":"transitive_dep+","bazel_tools":"bazel_tools"}}' ;;
    esac
  done
  exit 0
fi
if echo "$args" | grep -q "mod show_repo"; then
  cat "{repos}"
  echo "$err" >&2; echo "$marker" >&2; exit 2
fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output_file" ]; then
    cp "{query}" "$2"
    exit 0
  fi
  shift
done
exit 1
"#,
            calls = calls.display(),
            repos = repo_proto.display(),
            query = query_proto.display(),
        );
        fs::write(&script, &body).unwrap();
        script
    }

    #[cfg(unix)]
    fn rule_with_inputs(name: &str, inputs: &[&str]) -> Target {
        let mut target = Target::default();
        target.r#type = target::Discriminator::Rule;
        target.rule = buffa::MessageField::some(Rule {
            name: name.to_owned(),
            rule_class: "sh_library".to_owned(),
            rule_input: inputs.iter().map(|input| (*input).to_owned()).collect(),
            ..Default::default()
        });
        target
    }

    /// The module repositories are hashed although `bazel mod` exits 2 over the failed
    /// extension, and the extension's own repository, which the root imports, is left out
    /// of the `show_repo` batch instead of failing it.
    #[test]
    #[cfg(unix)]
    fn query_bzlmod_repos_skips_a_failed_extension() {
        let workspace = tempfile::tempdir().unwrap();
        let script = failed_extension_script(workspace.path(), &[rule_target("//app:lib")]);
        let options = probe_options(workspace.path(), script);

        let targets = options.query_all_targets().unwrap();
        let names = targets
            .iter()
            .filter_map(target_name)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from([
                "//app:lib",
                "//external:direct_dep",
                "//external:transitive_dep",
            ])
        );
        let calls = fs::read_to_string(workspace.path().join("calls.log")).unwrap();
        let show_repo = calls
            .lines()
            .filter(|line| line.contains("mod show_repo"))
            .collect::<Vec<_>>();
        assert!(
            show_repo.last().is_some_and(|line| {
                line.contains("@@direct_dep+")
                    && line.contains("@@transitive_dep+")
                    && !line.contains("missing_repo")
            }),
            "{calls}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn isolated_root_requires_a_supported_complete_ordinary_survey() {
        let refuses = |options: &BazelOptions, expected: &str| {
            let mut transformed = false;
            let result = options.query_all_targets_with(|_, _| transformed = true, None);
            let error = match result {
                Ok(_) => panic!("isolated root unexpectedly accepted"),
                Err(error) => error,
            };
            let error = format!("{error:#}");
            assert!(error.contains(expected), "{error}");
            assert!(
                error.contains(&format!(
                    "--isolatedDependencyRoot={}",
                    options.isolated_dependency_root.as_deref().unwrap()
                )),
                "{error}"
            );
            assert!(
                !transformed,
                "repository targets were hashed before admission"
            );
        };
        let workspace = tempfile::tempdir().unwrap();
        let script = failed_extension_script(workspace.path(), &[rule_target("//app:lib")]);
        let mut options = probe_options(workspace.path(), script.clone());
        options.isolated_dependency_root = Some("@missing_repo".into());
        refuses(
            &options,
            "module extension @@transitive_dep+//:extensions.bzl%broken failed",
        );

        let body = fs::read_to_string(&script)
            .unwrap()
            .replace("Build label: 8.7.0", "Build label: 9.0.0");
        fs::write(script, body).unwrap();
        refuses(
            &options,
            "Bazel 9.0.0 does not support Bzlmod repository discovery",
        );
        options.isolated_dependency_root = None;
        assert_eq!(
            options
                .query_all_targets()
                .unwrap()
                .iter()
                .filter_map(target_name)
                .collect::<Vec<_>>(),
            ["//app:lib"]
        );

        options.isolated_dependency_root = Some("@missing_repo".into());
        options.use_cquery = true;
        let calls = query_calls(workspace.path());
        refuses(&options, "requires ordinary query");
        assert_eq!(query_calls(workspace.path()), calls);

        let disabled = tempfile::tempdir().unwrap();
        let script = query_script(disabled.path(), "8.7.0", &[], 0);
        let mut options = probe_options(disabled.path(), script);
        options.isolated_dependency_root = Some("@hub".into());
        refuses(&options, "Bzlmod repository discovery is unavailable");
    }

    /// A target that depends on a repository of the failed extension has an input the
    /// hashes cannot cover: an error, or a warning under `--keep_going`.
    #[test]
    #[cfg(unix)]
    fn referenced_failed_extension_repo_is_an_error_without_keep_going() {
        let workspace = tempfile::tempdir().unwrap();
        let script = failed_extension_script(
            workspace.path(),
            &[
                rule_target("//app:lib"),
                rule_with_inputs("//app:uses_missing", &["//app:lib", "@missing_repo//:x"]),
                rule_with_inputs(
                    "//app:uses_missing_canonical",
                    &["@@transitive_dep++broken+unimported_repo//:x"],
                ),
            ],
        );
        let mut options = probe_options(workspace.path(), script);

        let error = options.query_all_targets().unwrap_err().to_string();
        assert!(
            error.contains(
                "//app:uses_missing depends on @missing_repo//:x, whose repository mapping failed"
            ),
            "{error}"
        );
        assert!(
            error.contains("reported module extensions: @@transitive_dep+//:extensions.bzl%broken"),
            "{error}"
        );
        assert!(
            error.contains(
                "//app:uses_missing_canonical depends on @@transitive_dep++broken+unimported_repo//:x"
            ),
            "{error}"
        );

        options.keep_going = true;
        let targets = options.query_all_targets().unwrap();
        let names = targets
            .iter()
            .filter_map(target_name)
            .collect::<BTreeSet<_>>();
        assert!(names.contains("//app:uses_missing"), "{names:?}");
        assert!(names.contains("//external:direct_dep"), "{names:?}");
    }

    fn configured(
        target: Target,
        checksum: Option<&str>,
        configuration_id: u32,
    ) -> ConfiguredTarget {
        ConfiguredTarget {
            target: buffa::MessageField::some(target),
            configuration: match checksum {
                Some(checksum) => buffa::MessageField::some(Configuration {
                    checksum: checksum.to_owned(),
                    ..Default::default()
                }),
                None => buffa::MessageField::none(),
            },
            configuration_id,
            ..Default::default()
        }
    }

    fn results(results: Vec<ConfiguredTarget>) -> CqueryResult {
        CqueryResult {
            results,
            ..Default::default()
        }
    }

    #[test]
    fn cquery_targets_are_named_by_their_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let source = Target {
            r#type: target::Discriminator::SourceFile,
            source_file: buffa::MessageField::some(SourceFile {
                name: "//a:a.txt".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let generated = Target {
            r#type: target::Discriminator::GeneratedFile,
            generated_file: buffa::MessageField::some(GeneratedFile {
                name: "//a:out".into(),
                generating_rule: "//a:a".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        // Bazel streams the configuration table after the results that refer to it, so a
        // result without an inline checksum is named once the stream has ended.
        let messages = [
            results(vec![configured(rule_target("//a:a"), Some("abc123"), 1)]),
            results(vec![configured(rule_target("//a:a"), None, 2)]),
            results(vec![
                configured(source, Some("null"), 0),
                configured(generated, Some("abc123"), 1),
            ]),
            CqueryResult {
                configurations: vec![Configuration {
                    id: 2,
                    checksum: "def456".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ];
        let streamed = directory.path().join("cquery-stream.pb");
        write_delimited(&streamed, &messages);
        let mut seen = Vec::new();
        let targets = decode_cquery_stream(&streamed, true, &mut |batch| {
            seen.extend(
                batch
                    .iter()
                    .map(|target| target_name(target).unwrap().to_owned()),
            )
        })
        .unwrap();
        let names = targets.iter().filter_map(target_name).collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "//a:a|abc123",
                "//a:a.txt",
                "//a:out|abc123",
                "//a:a|def456"
            ]
        );
        assert_eq!(seen, names, "the transform sees configured names");
        assert_eq!(
            targets[2]
                .generated_file
                .as_option()
                .unwrap()
                .generating_rule,
            "//a:a|abc123"
        );
        assert_eq!(deduplicate_targets(targets).unwrap().len(), 4);

        let non_streamed = directory.path().join("cquery.pb");
        let mut combined = results(vec![configured(rule_target("//a:a"), None, 2)]);
        combined.configurations = vec![Configuration {
            id: 2,
            checksum: "def456".into(),
            ..Default::default()
        }];
        fs::write(&non_streamed, combined.encode_to_vec()).unwrap();
        let targets = decode_cquery_stream(&non_streamed, false, &mut |_| {}).unwrap();
        assert_eq!(target_name(&targets[0]), Some("//a:a|def456"));
    }

    #[test]
    fn configured_keys_split_into_label_and_checksum() {
        assert_eq!(configured_key("//a:a", "0f"), "//a:a|0f");
        assert_eq!(split_configured("//a:a|abc123"), ("//a:a", Some("abc123")));
        assert_eq!(split_configured("//a:a"), ("//a:a", None));
        // `|` is legal in a target name; only a hexadecimal suffix is a checksum.
        assert_eq!(split_configured("//a:odd|name"), ("//a:odd|name", None));
        assert_eq!(
            split_configured("//a:odd|name|0f"),
            ("//a:odd|name", Some("0f"))
        );
        assert_eq!(target_label("//a:a|"), "//a:a|");
        assert_eq!(target_label("//a:a|abc123"), "//a:a");
    }

    /// Fake Bazel for the `query`/`cquery` runners: `version` reports `version`; the
    /// compatible-target cquery (`--output starlark`) lists `compatible`, one per line, with a
    /// blank line that the runner must ignore; the proto cquery copies `cquery_proto` to its
    /// `--output_file`, or prints it when the runner redirects stdout instead (a Bazel older
    /// than 8.2); `query` copies `query_proto` the same way and exits with `query_exit`,
    /// reporting on stderr when that is non-zero. Every invocation is appended to `calls.log`.
    #[cfg(unix)]
    fn query_script(
        workspace: &Path,
        version: &str,
        compatible: &[&str],
        query_exit: i32,
    ) -> PathBuf {
        let result = results(vec![
            configured(rule_target("//app:lib"), Some("abc123"), 1),
            configured(rule_target("//app:incompatible"), Some("abc123"), 1),
            configured(rule_target("//app:tool"), Some("def456"), 2),
        ]);
        let streamed_proto = workspace.join("cquery-stream.pb");
        write_delimited(&streamed_proto, std::slice::from_ref(&result));
        let proto = workspace.join("cquery-result.pb");
        fs::write(&proto, result.encode_to_vec()).unwrap();
        let query_proto = workspace.join("query-result.pb");
        write_delimited(&query_proto, &[rule_target("//app:lib")]);
        let script = workspace.join("fake-bazel.sh");
        let body = format!(
            r#"#!/bin/sh
echo "$*" >> "{calls}"
copy_or_print() {{
  for arg do
    if [ "$next" = 1 ]; then cp "$1" "$arg"; return 0; fi
    [ "$arg" = "--output_file" ] && next=1
  done
  cat "$1"
}}
if [ "$1" = version ]; then
  echo "Build label: {version}"
  exit 0
fi
if [ "$1" = cquery ]; then
  if echo "$*" | grep -q -- "--output starlark"; then
    printf '{compatible}'
    exit 0
  fi
  if echo "$*" | grep -q -- "--output proto"; then
    copy_or_print "{proto}" "$@"
  else
    copy_or_print "{streamed}" "$@"
  fi
  exit 0
fi
if [ "$1" = query ]; then
  copy_or_print "{query}" "$@"
  if [ {query_exit} -ne 0 ]; then
    echo "ERROR: no such package 'missing': BUILD file not found" >&2
  fi
  exit {query_exit}
fi
exit 1
"#,
            calls = workspace.join("calls.log").display(),
            compatible = compatible
                .iter()
                .map(|label| format!("{label}\n"))
                .collect::<String>()
                .replacen('\n', "\n\n", 1),
            streamed = streamed_proto.display(),
            proto = proto.display(),
            query = query_proto.display(),
        );
        fs::write(&script, body).unwrap();
        script
    }

    #[cfg(unix)]
    fn query_calls(workspace: &Path) -> Vec<String> {
        fs::read_to_string(workspace.join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// `cquery` first asks Bazel which targets are compatible with the target platform, then
    /// streams the configured targets and keeps only the compatible ones, matched by label
    /// with the configuration checksum stripped. A Bazel before 7.0 has no streamed cquery
    /// output, so the runner asks for `--output proto` instead, and one before 8.2 has no
    /// `--output_file`, so stdout is redirected to the output file.
    #[test]
    #[cfg(unix)]
    fn cquery_filters_to_compatible_targets_across_bazel_versions() {
        for (version, output, output_file) in [
            ("8.7.0", "streamed_proto", true),
            ("7.4.1", "streamed_proto", false),
            ("6.5.0", "proto", false),
        ] {
            let workspace = tempfile::tempdir().unwrap();
            let script = query_script(workspace.path(), version, &["//app:lib", "//app:tool"], 0);
            let mut options = probe_options(workspace.path(), script);
            options.use_cquery = true;
            options.cquery_options = vec!["--define=flavor=test".into()];
            options.command_options = vec!["--query-only".into()];

            let targets = options.query("deps(//app:all)", true).unwrap();
            let names = targets.iter().filter_map(target_name).collect::<Vec<_>>();
            assert_eq!(
                names,
                ["//app:lib|abc123", "//app:tool|def456"],
                "Bazel {version}: the incompatible target is dropped, the rest keep their configuration"
            );

            let calls = query_calls(workspace.path());
            assert_eq!(calls.len(), 3, "{calls:?}");
            assert_eq!(calls[0], "version");
            let compatible = &calls[1];
            assert!(
                compatible.starts_with("cquery --output starlark --starlark:file "),
                "{compatible}"
            );
            assert!(
                compatible.contains("--define=flavor=test --consistent_labels --query_file"),
                "{compatible}"
            );
            assert!(!compatible.contains("--query-only"), "{compatible}");
            let streamed = &calls[2];
            assert!(
                streamed.starts_with(&format!(
                    "cquery --transitions=lite --output {output} --proto:instantiation_stack --define=flavor=test --consistent_labels --query_file "
                )),
                "Bazel {version}: {streamed}"
            );
            assert!(!streamed.contains("--order_output=no"), "{streamed}");
            assert!(!streamed.contains("--keep_going"), "{streamed}");
            assert_eq!(
                streamed.contains("--output_file"),
                output_file,
                "Bazel {version}: {streamed}"
            );
        }
    }

    /// A failed compatible-target cquery stops the query instead of silently keeping every
    /// target, and a plain `query` that exits non-zero is an error that quotes Bazel's stderr --
    /// unless `--keep_going` was asked for and Bazel exited 3, the code it uses for a partial
    /// answer, in which case the output it did produce is used.
    #[test]
    #[cfg(unix)]
    fn query_surfaces_bazel_failures_and_tolerates_partial_answers_with_keep_going() {
        let workspace = tempfile::tempdir().unwrap();
        let script = query_script(workspace.path(), "8.7.0", &[], 1);
        let mut options = probe_options(workspace.path(), script);
        options.command_options = vec!["--noimplicit_deps".into()];

        let error = options.query("//app:all", false).unwrap_err().to_string();
        assert!(
            error.contains("Bazel query failed, exit code 1: ERROR: no such package 'missing'"),
            "{error}"
        );
        let calls = query_calls(workspace.path());
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(
            calls[1].starts_with(
                "query --output streamed_proto --proto:instantiation_stack --order_output=no --noimplicit_deps --query_file "
            ),
            "{}",
            calls[1]
        );

        // Exit code 1 is still an error under --keep_going; only 3 is a partial answer.
        options.keep_going = true;
        let error = options.query("//app:all", false).unwrap_err().to_string();
        assert!(error.contains("Bazel query failed, exit code 1"), "{error}");
        assert!(
            query_calls(workspace.path())[3].contains("--keep_going"),
            "{:?}",
            query_calls(workspace.path())
        );

        let partial = tempfile::tempdir().unwrap();
        let script = query_script(partial.path(), "8.7.0", &[], 3);
        let mut options = probe_options(partial.path(), script);
        let error = options.query("//app:all", false).unwrap_err().to_string();
        assert!(error.contains("Bazel query failed, exit code 3"), "{error}");
        options.keep_going = true;
        let targets = options.query("//app:all", false).unwrap();
        assert_eq!(
            targets.iter().filter_map(target_name).collect::<Vec<_>>(),
            ["//app:lib"]
        );

        let partial = options
            .exact_toolchain_rows(
                &BTreeSet::from(["//app:lib".into()]),
                Some(BazelVersion(8, 7, 0)),
            )
            .unwrap();
        assert!(!partial.complete);
        assert_eq!(
            partial
                .rows
                .iter()
                .filter_map(target_name)
                .collect::<Vec<_>>(),
            ["//app:lib"]
        );

        // The compatible-target cquery failing is an error of its own, before any proto cquery.
        let incompatible = tempfile::tempdir().unwrap();
        let script = incompatible.path().join("fake-bazel.sh");
        fs::write(
            &script,
            "#!/bin/sh\necho \"$*\" >> calls.log\nif [ \"$1\" = version ]; then echo 'Build label: 8.7.0'; exit 0; fi\necho 'ERROR: no such target' >&2\nexit 1\n",
        )
        .unwrap();
        let mut options = probe_options(incompatible.path(), script);
        options.use_cquery = true;
        let error = options
            .query("deps(//app:all)", true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("compatible-target cquery failed: ERROR: no such target"),
            "{error}"
        );
        assert_eq!(query_calls(incompatible.path()).len(), 2);
    }
}
