#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{fmt::Write as _, hint::black_box, time::Instant};
    use syrox_engine::{project::CheckConfiguration, project::open_project_analysis_with};
    use syrox_lang::{
        analysis::AnalysisCancellation, analysis::AnalysisHost, analysis::SemanticAnalysis,
        source::SourceId,
    };

    fn measure(mut query: impl FnMut(), count: usize) -> (u128, u128, u128) {
        let mut times = Vec::with_capacity(count);
        for _ in 0..count {
            let start = Instant::now();
            query();
            times.push(start.elapsed().as_nanos());
        }
        times.sort_unstable();
        (
            times[count / 2] / 1000,
            times[(count * 95).div_ceil(100) - 1] / 1000,
            times[count - 1] / 1000,
        )
    }

    fn report(name: &str, count: usize, query: impl FnMut()) {
        let (p50, p95, max) = measure(query, count);
        println!("{name}: samples={count} p50_us={p50} p95_us={p95} max_us={max}");
    }

    fn profile_file(body: &str, cancel: &AnalysisCancellation) {
        report("syntax_cold_file", 30, || {
            let mut host = AnalysisHost::default();
            host.set_disk("file", body).unwrap();
            black_box(
                host.snapshot()
                    .document("file")
                    .unwrap()
                    .parsed(cancel)
                    .unwrap(),
            );
        });
        let broken = format!("{body}outputs {{ item: I = I(1) }}");
        report("fixes_cold_file", 30, || {
            let mut host = AnalysisHost::default();
            host.set_disk("file", &broken).unwrap();
            assert_eq!(
                black_box(
                    host.snapshot()
                        .document("file")
                        .unwrap()
                        .syntax_fixes(cancel)
                        .unwrap()
                )
                .len(),
                1
            );
        });
    }

    fn profile_symbols(
        analysis: &SemanticAnalysis,
        source: SourceId,
        cancel: &AnalysisCancellation,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let start = Instant::now();
        black_box(analysis.occurrences(cancel)?);
        println!("symbols_cold_us={}", start.elapsed().as_micros());
        report("semantic_tokens_source_query", 100, || {
            black_box(analysis.occurrences_in(source, cancel).unwrap());
        });
        report("type_labels", 30, || {
            for item in analysis.items().take(64) {
                if let Some(ty) = analysis.function_type(item.id()) {
                    black_box(analysis.display_type(ty));
                }
            }
        });
        Ok(())
    }

    fn profile_owner(analysis: &SemanticAnalysis, source: SourceId, cancel: &AnalysisCancellation) {
        assert!(!analysis.resolution_owners_truncated());
        let owner = analysis
            .resolution_owners()
            .find(|(key, span)| {
                span.source_id() == source && key.path.last().is_some_and(|name| name == "f00")
            })
            .unwrap()
            .0;
        report("owner_resolution_query", 100, || {
            black_box(
                analysis
                    .owner_resolution(owner, cancel)
                    .unwrap()
                    .unwrap(),
            );
        });
        let start = Instant::now();
        let dependencies = analysis
            .owner_type_dependencies(owner, cancel)
            .unwrap();
        println!(
            "owner_type_dependencies_cold_us={} available={} interfaces_truncated={}",
            start.elapsed().as_micros(),
            dependencies.is_some(),
            analysis
                .type_interfaces_truncated(cancel)
                .unwrap(),
        );
        if dependencies.is_some() {
            report("owner_type_dependencies_query", 100, || {
                black_box(
                    analysis
                        .owner_type_dependencies(owner, cancel)
                        .unwrap()
                        .unwrap(),
                );
            });
            report("owner_checked_facts_remap", 30, || {
                black_box(
                    analysis
                        .remap_checked_body_from(analysis, owner, cancel)
                        .unwrap()
                        .unwrap(),
                );
            });
            if let Some(journal) = analysis
                .remap_body_effects_from(analysis, owner, cancel)
                .unwrap()
            {
                println!(
                    "owner_effect_observations={}",
                    journal.observation_count()
                );
                report("owner_body_effects_remap", 30, || {
                    black_box(
                        analysis
                            .remap_body_effects_from(analysis, owner, cancel)
                            .unwrap()
                            .unwrap(),
                    );
                });
                assert_eq!(journal.entry().generic_instances, 0);
                let input = syrox_lang::checker::BodyReplayState {
                    budget: journal.entry(),
                    instances: std::collections::BTreeSet::new(),
                };
                report("owner_body_effects_replay", 100, || {
                    let result = journal
                        .replay(
                            &input,
                            syrox_lang::checker::CheckLimits::default(),
                            cancel,
                        )
                        .unwrap()
                        .unwrap();
                    assert_eq!(result.budget, journal.exit());
                    black_box(result);
                });
            } else {
                println!("owner_body_effects_available=false");
            }
        }
    }

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        let arguments: Vec<_> = std::env::args().skip(1).collect();
        let modules: usize = arguments
            .first()
            .map_or(Ok(64), |value| value.parse())?;
        let functions: usize = arguments
            .get(1)
            .map_or(Ok(16), |value| value.parse())?;
        if !(1..=256).contains(&modules) || !(1..=64).contains(&functions) {
            return Err("corpus bounds: 1..256 modules, 1..64 functions".into());
        }
        let root = tempfile::tempdir()?;
        std::fs::create_dir(root.path().join("recipes"))?;
        let main =
            "inputs { lib = \"modules:recipes\"; } fn run() -> lib::m000::I { lib::m000::f00() }";
        std::fs::write(root.path().join("main.srx"), main)?;
        let mut body = "pub value I(int);\n".to_owned();
        for index in 0..functions {
            writeln!(body, "pub fn f{index:02}() -> I {{ I(1) }}")?;
        }
        for index in 0..modules {
            std::fs::write(
                root.path()
                    .join(format!("recipes/m{index:03}.srx")),
                &body,
            )?;
        }
        println!(
            "profile={} modules={modules} functions_per_module={functions} sources={} bytes={}",
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            modules + 1,
            main.len() + modules * body.len()
        );
        let cancel = AnalysisCancellation::default();
        profile_file(&body, &cancel);
        let start = Instant::now();
        let mut project = open_project_analysis_with(root.path(), &CheckConfiguration::default())?;
        println!("load_us={}", start.elapsed().as_micros());
        let snapshot = project.snapshot();
        let edited_id = snapshot
            .sources()
            .iter()
            .find(|(_, source)| source.name().ends_with("m000.srx"))
            .unwrap()
            .0;
        let main_id = snapshot
            .sources()
            .iter()
            .find(|(_, source)| source.text() == main)
            .unwrap()
            .0;
        let document = snapshot.document(edited_id).unwrap();
        document.parsed(&cancel)?;
        report("syntax_cached_file", 100, || {
            black_box(document.parsed(&cancel).unwrap());
        });
        let start = Instant::now();
        let analysis = snapshot.analyze(&cancel)?;
        assert!(
            analysis.diagnostics().is_empty(),
            "{:?}",
            analysis.diagnostics()
        );
        println!("semantic_cold_us={}", start.elapsed().as_micros());
        profile_owner(&analysis, edited_id, &cancel);
        profile_symbols(&analysis, edited_id, &cancel)?;
        report("semantic_cached", 100, || {
            black_box(project.snapshot().analyze(&cancel).unwrap());
        });
        let mut version = 0;
        report("semantic_same_text_revision", 30, || {
            version += 1;
            project
                .set_overlay(edited_id, version, &body)
                .unwrap();
            let result = project.snapshot().analyze(&cancel).unwrap();
            assert!(std::ptr::eq(analysis.sources(), result.sources()));
            black_box(result);
        });
        let offset = u32::try_from(main.find("lib::m000::f00").unwrap()).unwrap();
        report("completion", 30, || {
            let candidates = black_box(analysis.complete_path(
                main_id,
                offset,
                &["lib".into(), "m000".into()],
                "f",
            ));
            assert_eq!(candidates.len(), functions);
        });
        report("semantic_body_edit", 10, || {
            version += 1;
            let changed = body.replace(
                "I(1)",
                if version % 2 == 0 {
                    "I(2)"
                } else {
                    "I(3)"
                },
            );
            project
                .set_overlay(edited_id, version, &changed)
                .unwrap();
            let result = black_box(project.snapshot().analyze(&cancel).unwrap());
            assert!(result.diagnostics().is_empty());
        });
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status
                .lines()
                .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
            {
                println!("{line}");
            }
        }
        Ok(())
    }
}
