const state = {
    dashboard: null,
};

const formatNumber = value => new Intl.NumberFormat("en-US").format(value ?? 0);
const formatSeconds = value => `${(value ?? 0).toFixed(4)}s`;

function renderHero(project, latestRun) {
    document.getElementById("project-title").textContent = project.title;
    document.getElementById("project-tagline").textContent = project.tagline;
    document.getElementById("repo-link").href = project.repo_url;
    document.getElementById("footer-copy").textContent = `Dashboard generated from ${latestRun?.result_count ?? 0} structured strategy results.`;

    const metrics = [
        {
            label: "Strategies",
            value: latestRun?.result_count ?? 0,
        },
        {
            label: "Attempts",
            value: formatNumber(latestRun?.totals?.attempts ?? 0),
        },
        {
            label: "Unique Attempts",
            value: formatNumber(latestRun?.totals?.unique_attempts ?? 0),
        },
        {
            label: "Elapsed",
            value: formatSeconds(latestRun?.totals?.elapsed_seconds ?? 0),
        },
    ];

    document.getElementById("hero-metrics").innerHTML = metrics
        .map(metric => `
            <article class="metric-card">
                <p class="metric-label">${metric.label}</p>
                <p class="metric-value">${metric.value}</p>
            </article>
        `)
        .join("");
}

function renderAnchors(anchors) {
    const container = document.getElementById("anchor-grid");
    container.innerHTML = anchors
        .map(anchor => `
            <article class="anchor-card">
                <p class="anchor-range">${anchor.start_index}-${anchor.end_index}</p>
                <h3>${anchor.plaintext}</h3>
                <p class="mono">Cipher: ${anchor.ciphertext}</p>
                <p class="mono">Shift letters: ${anchor.shift_letters}</p>
            </article>
        `)
        .join("");
}

function renderBenchmarks(benchmarks) {
    const maxSpeed = Math.max(...benchmarks.map(item => item.speed_per_second));
    document.getElementById("benchmark-grid").innerHTML = benchmarks
        .map(benchmark => {
            const width = Math.max(12, Math.round((benchmark.speed_per_second / maxSpeed) * 100));
            return `
                <article class="benchmark-card">
                    <div class="benchmark-topline">
                        <h3>${benchmark.label}</h3>
                        <p class="mono">${benchmark.display_speed}</p>
                    </div>
                    <div class="benchmark-bar">
                        <span style="width:${width}%"></span>
                    </div>
                    <p>${benchmark.notes}</p>
                </article>
            `;
        })
        .join("");
}

function renderResearchMemory(researchMemory) {
    const generatedAt = document.getElementById("memory-generated-at");
    const summary = document.getElementById("memory-summary");
    const grid = document.getElementById("memory-grid");

    if (!researchMemory) {
        generatedAt.textContent = "No persistent ledger has been generated yet.";
        summary.innerHTML = "";
        grid.innerHTML = `
            <article class="memory-card memory-empty">
                <p>Run the toolkit with a ledger output path to accumulate candidate evidence across sweeps.</p>
            </article>
        `;
        return;
    }

    generatedAt.textContent = `Updated ${new Date(researchMemory.updated_at).toLocaleString()}`;
    summary.innerHTML = `
        <article class="summary-card">
            <p class="summary-label">Ledger Runs</p>
            <p class="summary-value">${formatNumber(researchMemory.runs_merged)}</p>
        </article>
        <article class="summary-card">
            <p class="summary-label">Observations</p>
            <p class="summary-value">${formatNumber(researchMemory.observation_count)}</p>
        </article>
        <article class="summary-card">
            <p class="summary-label">Candidates</p>
            <p class="summary-value">${formatNumber(researchMemory.candidate_count)}</p>
        </article>
        <article class="summary-card">
            <p class="summary-label">Strategies Seen</p>
            <p class="summary-value">${formatNumber(researchMemory.strategy_count)}</p>
        </article>
    `;

    grid.innerHTML = (researchMemory.top_candidates ?? [])
        .map(candidate => `
            <article class="memory-card">
                <div class="memory-topline">
                    <div>
                        <p class="catalog-id">Consensus ${formatNumber(candidate.consensus_score)}</p>
                        <h3>${candidate.best_strategy_name ?? "Candidate Memory"}</h3>
                    </div>
                    <p class="mono">Best ${formatNumber(candidate.best_score)}</p>
                </div>
                <p class="memory-preview mono">${candidate.preview}</p>
                <p class="memory-meta">Seen ${formatNumber(candidate.observation_count)} times across ${formatNumber(candidate.strategy_count)} strategies.</p>
                <p class="memory-chain mono">${(candidate.best_transform_chain ?? []).join(" -> ") || "direct"}</p>
                <p class="memory-clues">${(candidate.matched_clues ?? []).join(", ") || "No matched clues yet"}</p>
            </article>
        `)
        .join("");
}

function renderExperimentPlan(researchMemory) {
    const generatedAt = document.getElementById("plan-generated-at");
    const grid = document.getElementById("plan-grid");
    const experimentPlan = researchMemory?.experiment_plan;

    if (!experimentPlan?.enabled) {
        generatedAt.textContent = researchMemory
            ? "The ledger needs stronger cross-run evidence before it can rank next experiments."
            : "Generate a research ledger to unlock explicit next-experiment planning.";
        grid.innerHTML = `
            <article class="plan-card plan-empty">
                <p>Recommendations will appear here once the ledger has enough retained candidates to compare promising families against coverage gaps.</p>
            </article>
        `;
        return;
    }

    generatedAt.textContent = `Planned from ${formatNumber(experimentPlan.source_candidate_count ?? 0)} retained candidates.`;
    grid.innerHTML = (experimentPlan.recommended_experiments ?? [])
        .map(experiment => {
            const strategies = (experiment.target_strategies ?? [])
                .map(strategy => `<span class="strategy-pill">[${strategy.id}] ${strategy.name}</span>`)
                .join("");
            const hints = Object.entries(experiment.parameter_hints ?? {})
                .map(([name, values]) => `<span class="hint-pill">${name}: ${(values ?? []).join(", ")}</span>`)
                .join("");
            const clues = (experiment.coverage?.supporting_clues ?? []).join(", ") || "No supporting clues yet";
            const observed = (experiment.coverage?.observed_strategy_ids ?? []).join(", ") || "none";
            const command = experiment.suggested_runs?.[0]?.command ?? "";
            return `
                <article class="plan-card">
                    <div class="plan-topline">
                        <div>
                            <p class="catalog-id">Priority ${formatNumber(experiment.priority_score)}</p>
                            <h3>${experiment.title}</h3>
                        </div>
                        <p class="mono">Rank ${experiment.rank}</p>
                    </div>
                    <p class="plan-thesis">${experiment.thesis}</p>
                    <div class="pill-row">${strategies || '<span class="strategy-pill">No strategy targets yet</span>'}</div>
                    <div class="pill-row">${hints || '<span class="hint-pill">No seed hints yet</span>'}</div>
                    <div class="plan-metrics">
                        <span>Evidence ${formatNumber(experiment.evidence_score)}</span>
                        <span>Gap ${formatNumber(experiment.underexplored_score)}</span>
                        <span>Observed ${observed}</span>
                    </div>
                    <p class="plan-clues">${clues}</p>
                    ${command ? `<p class="plan-command mono">${command}</p>` : ""}
                </article>
            `;
        })
        .join("");
}

function renderLatestRun(latestRun, generatedAt) {
    document.getElementById("run-generated-at").textContent = `Generated ${new Date(generatedAt).toLocaleString()}`;
    document.getElementById("run-summary").innerHTML = `
        <article class="summary-card">
            <p class="summary-label">Selection</p>
            <p class="summary-value">${latestRun.strategy_selection}</p>
        </article>
        <article class="summary-card">
            <p class="summary-label">Attempts</p>
            <p class="summary-value">${formatNumber(latestRun.totals.attempts)}</p>
        </article>
        <article class="summary-card">
            <p class="summary-label">Unique Attempts</p>
            <p class="summary-value">${formatNumber(latestRun.totals.unique_attempts)}</p>
        </article>
        <article class="summary-card">
            <p class="summary-label">Elapsed</p>
            <p class="summary-value">${formatSeconds(latestRun.totals.elapsed_seconds)}</p>
        </article>
    `;

    document.getElementById("run-results").innerHTML = latestRun.results
        .map(result => `
            <tr>
                <td>
                    <strong>[${result.strategy_id}] ${result.name}</strong>
                    <p>${result.summary}</p>
                </td>
                <td><span class="status ${result.status}">${result.status.replace("_", " ")}</span></td>
                <td class="mono">${formatNumber(result.metrics.attempts)}</td>
                <td class="mono">${formatSeconds(result.metrics.elapsed_seconds ?? 0)}</td>
                <td class="mono preview-cell">${result.best_preview || "-"}</td>
            </tr>
        `)
        .join("");
}

function renderCatalog(strategyCatalog, latestRun) {
    const resultsById = new Map((latestRun?.results ?? []).map(result => [result.strategy_id, result]));
    document.getElementById("catalog-grid").innerHTML = strategyCatalog
        .map(spec => {
            const result = resultsById.get(spec.id);
            return `
                <article class="catalog-card">
                    <p class="catalog-id">Strategy ${spec.id}</p>
                    <h3>${spec.name}</h3>
                    <p>${spec.objective}</p>
                    <p class="catalog-hypothesis">${spec.hypothesis}</p>
                    <div class="catalog-meta">
                        <span>${spec.category}</span>
                        <span class="status ${result?.status ?? "pending"}">${result?.status ?? "pending"}</span>
                    </div>
                </article>
            `;
        })
        .join("");
}

function revealOnScroll() {
    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add("visible");
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.12 });

    document.querySelectorAll(".reveal").forEach(element => observer.observe(element));
}

async function bootstrap() {
    const response = await fetch("data/dashboard.json", { cache: "no-store" });
    if (!response.ok) {
        throw new Error(`Failed to load dashboard data: ${response.status}`);
    }

    state.dashboard = await response.json();
    const {
        project,
        anchors,
        benchmarks,
        latest_run: latestRun,
        strategy_catalog: strategyCatalog,
        research_memory: researchMemory,
        generated_at: generatedAt,
    } = state.dashboard;

    renderHero(project, latestRun);
    renderAnchors(anchors);
    renderBenchmarks(benchmarks);
    renderResearchMemory(researchMemory);
    renderExperimentPlan(researchMemory);
    renderLatestRun(latestRun, generatedAt);
    renderCatalog(strategyCatalog, latestRun);
    revealOnScroll();
}

bootstrap().catch(error => {
    document.body.classList.add("load-error");
    document.getElementById("project-tagline").textContent = error.message;
    document.getElementById("run-generated-at").textContent = "Dashboard data could not be loaded.";
});
