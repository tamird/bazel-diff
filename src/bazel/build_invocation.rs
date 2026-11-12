use super::{split_configured, BazelOptions};
use crate::model::ConfiguredRoots;
use anyhow::{ensure, Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use tempfile::NamedTempFile;

pub struct BuildInvocation {
    configurations: BTreeMap<String, BTreeSet<String>>,
    _policy_rc: NamedTempFile,
}

impl BuildInvocation {
    pub fn check_roots(&self, roots: Option<&ConfiguredRoots>) -> Result<()> {
        let roots = roots.context("missing configured roots")?;
        for (label, key) in &roots.roots {
            ensure!(
                roots
                    .verified_roots
                    .as_ref()
                    .is_some_and(|verified| verified.contains_key(label)),
                "dependency traversal did not verify all inputs of {label}"
            );
            let (_, checksum) = split_configured(key);
            let label = label.trim_start_matches('@');
            ensure!(
                self.configurations
                    .get(label)
                    .is_some_and(|configs| configs.len() == 1
                        && checksum.is_some_and(|value| configs.contains(value))),
                "configured root {label} did not match the build's configuration"
            );
        }
        Ok(())
    }
}

impl BazelOptions {
    pub fn bind_build_invocation(&mut self, path: &Path) -> Result<BuildInvocation> {
        ensure!(
            self.use_cquery && self.cquery_root_expression.is_some(),
            "--buildEventJson requires --useCquery and --cqueryRootExpression"
        );
        let events = File::open(self.workspace.join(path))?;
        let mut build_or_test = false;
        let mut finished = false;
        let mut requested = BTreeSet::new();
        let mut configurations = BTreeMap::<String, BTreeSet<String>>::new();
        let mut options = None;
        for line in BufReader::new(events).lines() {
            let event: Value = serde_json::from_str(&line?)?;
            if let Some(command) = event.pointer("/started/command").and_then(Value::as_str) {
                build_or_test = matches!(command, "build" | "test");
            }
            if event.pointer("/id/buildFinished").is_some() {
                finished = event
                    .pointer("/finished/overallSuccess")
                    .and_then(Value::as_bool)
                    == Some(true)
                    || event
                        .pointer("/finished/exitCode/name")
                        .and_then(Value::as_str)
                        == Some("SUCCESS");
            }
            if event.pointer("/id/pattern").is_some() && event.get("expanded").is_some() {
                for child in event["children"].as_array().into_iter().flatten() {
                    if let Some(label) = child
                        .pointer("/targetConfigured/label")
                        .and_then(Value::as_str)
                    {
                        requested.insert(label.trim_start_matches('@').to_owned());
                    }
                }
            }
            if event
                .pointer("/structuredCommandLine/commandLineLabel")
                .and_then(Value::as_str)
                == Some("canonical")
            {
                options = event
                    .pointer("/structuredCommandLine/sections")
                    .and_then(Value::as_array)
                    .and_then(|sections| {
                        sections
                            .iter()
                            .find(|s| s["sectionLabel"] == "command options")
                    })
                    .and_then(|s| s.pointer("/optionList/option"))
                    .and_then(Value::as_array)
                    .cloned();
            }
            let Some(id) = event.pointer("/id/targetCompleted") else {
                continue;
            };
            if id.get("aspect").is_none()
                && (event.pointer("/aborted/reason").and_then(Value::as_str) == Some("NO_BUILD")
                    || event.pointer("/completed/success").and_then(Value::as_bool) == Some(true))
            {
                if let (Some(label), Some(config)) = (
                    id["label"].as_str(),
                    id.pointer("/configuration/id").and_then(Value::as_str),
                ) {
                    configurations
                        .entry(label.trim_start_matches('@').to_owned())
                        .or_default()
                        .insert(config.to_owned());
                }
            }
        }
        ensure!(
            build_or_test && finished,
            "expected a complete successful Bazel build or test event stream"
        );
        configurations.retain(|label, _| requested.contains(label));
        ensure!(
            !configurations.is_empty(),
            "build analysis reported no configured targets"
        );
        let options = options.context("build did not report its canonical command options")?;
        // Both flags allow multiple values. Appending them to the query would leave any
        // cquery-only or mod-only registrations and environment entries in effect.
        let mut policy = String::new();
        for (flag, commands) in [
            ("repo_env", &["cquery", "query", "mod", "info"][..]),
            ("extra_toolchains", &["cquery"][..]),
        ] {
            let mut body = String::new();
            let mut environment = BTreeMap::new();
            for option in options.iter().filter(|opt| opt["optionName"] == flag) {
                let value = option["optionValue"]
                    .as_str()
                    .context("missing Bazel option value")?;
                if flag == "repo_env" {
                    let name = value
                        .strip_prefix('=')
                        .unwrap_or(value)
                        .split('=')
                        .next()
                        .unwrap();
                    environment.insert(name, value);
                } else {
                    body += &format!("flag_value: {} ", serde_json::to_string(value)?);
                }
            }
            for (name, setting) in environment {
                ensure!(
                    setting.contains('='),
                    "build event does not record the inherited value of --repo_env={name}"
                );
                body += &format!("flag_value: {} ", serde_json::to_string(setting)?);
            }
            let operation = if body.is_empty() {
                "use_default {}".to_owned()
            } else {
                format!("set_value {{ {body}behavior: FINAL_VALUE_IGNORE_OVERRIDES }}")
            };
            policy += &format!("flag_policies {{ flag_name: {flag:?} ");
            for cmd in commands {
                policy += &format!("commands: {cmd:?} ");
            }
            policy += &format!("{operation} }} ");
        }
        ensure!(
            !self.no_bazelrc
                && !self
                    .startup_options
                    .iter()
                    .any(|s| s == "--ignore_all_rc_files"),
            "build binding needs Bazel rc loading"
        );
        let mut rc = NamedTempFile::new()?;
        // Bazel reads the policy from this private file. Repository environment values do
        // not appear in command diagnostics or process listings.
        writeln!(
            rc,
            "startup '--invocation_policy={}'",
            policy.replace('\'', "'\\''")
        )?;
        self.startup_options
            .insert(0, format!("--bazelrc={}", rc.path().display()));
        Ok(BuildInvocation {
            configurations,
            _policy_rc: rc,
        })
    }
}
