/* Kryptos K4 Research Dashboard */

const K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR";

const ANCHORS = {
    east: { start: 21, end: 24, plaintext: "EAST" },
    northeast: { start: 25, end: 33, plaintext: "NORTHEAST" },
    berlin: { start: 63, end: 68, plaintext: "BERLIN" },
    clock: { start: 69, end: 73, plaintext: "CLOCK" }
};

const STRATEGIES = [
    { id: 1, name: "Quagmire III Running Keys", cat: "classical", status: "eliminated" },
    { id: 2, name: "Spatial Matrix Reassembly", cat: "transposition", status: "tested" },
    { id: 3, name: "Hybrid Transposition Search", cat: "transposition", status: "partial" },
    { id: 4, name: "Quagmire III Autokey", cat: "classical", status: "eliminated" },
    { id: 5, name: "Geometric Grilles", cat: "masking", status: "tested" },
    { id: 6, name: "Chained Autokey", cat: "classical", status: "eliminated" },
    { id: 7, name: "Segmented Resets", cat: "segmentation", status: "tested" },
    { id: 8, name: "Shifted Running Keys", cat: "classical", status: "eliminated" },
    { id: 9, name: "External Text Running Key", cat: "historical", status: "partial" },
    { id: 10, name: "Fractionation Pipeline", cat: "fractionation", status: "partial" },
    { id: 11, name: "Corpus Running Key", cat: "historical", status: "partial" },
    { id: 12, name: "Periodic Transposition Hillclimb", cat: "transposition", status: "partial" },
    { id: 13, name: "Hybrid Pipeline Search", cat: "hybrid", status: "partial" },
    { id: 14, name: "Displacement Route Search", cat: "hybrid", status: "partial" },
    { id: 15, name: "Z340-Style Transposition Enumeration", cat: "transposition", status: "partial" },
    { id: 16, name: "SAT/SMT Constraint Elimination", cat: "elimination", status: "confirmed" },
    { id: 17, name: "Known-Plaintext Method Elimination", cat: "elimination", status: "confirmed" },
    { id: 18, name: "Alternating Optimization (Lasry)", cat: "hybrid", status: "partial" },
    { id: 19, name: "MCMC Key Search", cat: "hybrid", status: "partial" },
    { id: 20, name: "Generalized IC Fingerprinting", cat: "analysis", status: "confirmed" },
    { id: 21, name: "Gromark Cipher", cat: "classical", status: "eliminated" },
    { id: 22, name: "ML Cipher Type Classification", cat: "analysis", status: "confirmed" },
    { id: 23, name: "Bayesian Cipher Analysis", cat: "analysis", status: "confirmed" },
    { id: 24, name: "Neural Language Model Scoring", cat: "scoring", status: "confirmed" },
    { id: 25, name: "Beaufort/Quagmire Constraint Sweep", cat: "hybrid", status: "eliminated" },
    { id: 26, name: "LATITUDE Deep Investigation", cat: "hybrid", status: "inconclusive" },
    { id: 27, name: "Key Derivation Analysis", cat: "analysis", status: "inconclusive" },
    { id: 28, name: "Digraphic Cipher Sweep", cat: "classical", status: "unlikely" },
    { id: 29, name: "Dictionary Full-Text Scoring", cat: "scoring", status: "confirmed" },
    { id: 30, name: "Monoalphabetic + Transposition", cat: "elimination", status: "eliminated" },
    { id: 31, name: "Hill 2×2 + Transposition", cat: "elimination", status: "eliminated" },
    { id: 32, name: "Unknown-Source Running Key", cat: "historical", status: "partial" },
    { id: 33, name: "Hill 3×3 + Transposition", cat: "elimination", status: "tested" },
    { id: 34, name: "Crib-Dragging Autocorrelation", cat: "analysis", status: "confirmed" },
    { id: 35, name: "Pure Quagmire III Deep Search", cat: "classical", status: "tested" },
    { id: 36, name: "Anchor Position Sensitivity", cat: "analysis", status: "confirmed" },
    { id: 37, name: "Transposition + Unknown Running Key", cat: "hybrid", status: "partial" },
    { id: 38, name: "Carter Diary Running-Key Attack", cat: "historical", status: "eliminated" },
    { id: 39, name: "Carter Journals Exhaustive Attack", cat: "historical", status: "eliminated" },
    { id: 40, name: "Mathematical Key Generation", cat: "analysis", status: "eliminated" },
];

/* ── K4 visualization ── */
function renderK4() {
    const container = document.getElementById("k4-text");
    if (!container) return;

    let html = "";
    for (let i = 0; i < K4.length; i++) {
        let cls = "unknown";
        let title = `pos ${i}: ${K4[i]}`;

        if ((i >= 21 && i <= 24) || (i >= 25 && i <= 33)) {
            cls = "known-east";
            const anchor = i <= 24 ? ANCHORS.east : ANCHORS.northeast;
            const pt = i <= 24
                ? anchor.plaintext[i - anchor.start]
                : ANCHORS.northeast.plaintext[i - ANCHORS.northeast.start];
            title = `pos ${i}: ${K4[i]} → ${pt}`;
        } else if (i >= 63 && i <= 68) {
            cls = "known-berlin";
            title = `pos ${i}: ${K4[i]} → ${ANCHORS.berlin.plaintext[i - 63]}`;
        } else if (i >= 69 && i <= 73) {
            cls = "known-berlin";
            title = `pos ${i}: ${K4[i]} → ${ANCHORS.clock.plaintext[i - 69]}`;
        }

        html += `<span class="k4-char ${cls}" title="${title}">${K4[i]}</span>`;
    }
    container.innerHTML = html;
}

/* ── Strategy catalog ── */
function renderCatalog() {
    const grid = document.getElementById("catalog-grid");
    if (!grid) return;

    const statusColors = {
        eliminated: "#ff6b6b",
        unlikely: "#ff835e",
        partial: "#8b9ea3",
        tested: "#8b9ea3",
        confirmed: "#91d98c",
        inconclusive: "#c6a86d",
    };

    const statusLabels = {
        eliminated: "✗ Eliminated",
        unlikely: "△ Unlikely",
        partial: "◐ Partial",
        tested: "◐ Tested",
        confirmed: "✔ Confirmed",
        inconclusive: "? Inconclusive",
    };

    const catColors = {
        classical: "var(--teal)",
        transposition: "var(--brass)",
        hybrid: "#b89dff",
        elimination: "#ff6b6b",
        analysis: "#91d98c",
        scoring: "#73cdbf",
        historical: "#c6a86d",
        fractionation: "#ff835e",
        masking: "#8b9ea3",
        segmentation: "#8b9ea3",
    };

    let html = "";
    for (const s of STRATEGIES) {
        const sc = statusColors[s.status] || "#8b9ea3";
        const sl = statusLabels[s.status] || s.status;
        const cc = catColors[s.cat] || "var(--muted)";
        html += `<div class="catalog-card" style="border-left: 3px solid ${sc}">
            <div class="catalog-id" style="color:${sc}">${s.id}</div>
            <div class="catalog-body">
                <div class="catalog-name">${s.name}</div>
                <div class="catalog-meta">
                    <span class="catalog-cat" style="color:${cc}">${s.cat}</span>
                    <span class="catalog-status" style="color:${sc}">${sl}</span>
                </div>
            </div>
        </div>`;
    }
    grid.innerHTML = html;
}

/* ── Scroll reveal ── */
function initReveal() {
    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((e) => {
                if (e.isIntersecting) {
                    e.target.classList.add("visible");
                    observer.unobserve(e.target);
                }
            });
        },
        { threshold: 0.08 }
    );
    document.querySelectorAll(".reveal").forEach((el) => observer.observe(el));
}

/* ── Boot ── */
document.addEventListener("DOMContentLoaded", () => {
    renderK4();
    renderCatalog();
    initReveal();
});
