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
    const { project, anchors, benchmarks, latest_run: latestRun, strategy_catalog: strategyCatalog, generated_at: generatedAt } = state.dashboard;

    renderHero(project, latestRun);
    renderAnchors(anchors);
    renderBenchmarks(benchmarks);
    renderLatestRun(latestRun, generatedAt);
    renderCatalog(strategyCatalog, latestRun);
    revealOnScroll();
}

bootstrap().catch(error => {
    document.body.classList.add("load-error");
    document.getElementById("project-tagline").textContent = error.message;
    document.getElementById("run-generated-at").textContent = "Dashboard data could not be loaded.";
});
