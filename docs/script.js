// Assault Strategies Data parsed directly from walkthrough.md
const strategies = [
    {
        num: 2,
        name: "Spatial Matrix Masking",
        objective: "Determine if the K4 text is a 2D matrix where known plaintext clues are geometrically arranged prior to substitution.",
        result: "FAILURE. No direct spatial re-assembly generated the native 1D contiguous arrays of the target ciphertext."
    },
    {
        num: 3,
        name: "Index of Coincidence (IoC) Maximization",
        objective: "Use a randomized hill-climbing algorithm over 300,000 permutations to search for transposition grid-widths that maximize English standard IoC.",
        result: "FAILURE. Period 11 scored highest (0.0440) but algorithm could not reassemble contiguous key segments from a scrambled state."
    },
    {
        num: 1,
        name: "Quagmire III Running Key Tests",
        objective: "Hypothesized a Running Key cipher using the plaintexts of previously decrypted panels (K1, K2, K3).",
        result: "FAILURE. None of the resultant plaintexts aligned with Jim Sanborn's known anchors."
    },
    {
        num: 4,
        name: "Quagmire III Autokey",
        objective: "Determine if K4 plaintext/ciphertext acts as its own running key using 14 standard theme-relevant primers.",
        result: "FAILURE. Plaintexts remained highly scrambled."
    },
    {
        num: 5,
        name: "Vigenère Grille / Geometric Masking",
        objective: "Simulate a physical cut-out grille mask over a 7x14 geometric extraction grid.",
        result: "FAILURE. Mathematical grilles failed to reconstruct the contiguous known sequences."
    },
    {
        num: 6,
        name: "Chained / Multi-layered Autokey",
        objective: "Test the hypothesis of nested Autokey-on-Autokey encryption chain via 49 primer permutations.",
        result: "FAILURE. Dual-layered substitution yielded deeply randomized plaintexts."
    },
    {
        num: 7,
        name: "Segmented / Delimiter-based Decryption",
        objective: "Test theory that the character 'W' acts as a cipher reset/delimiter by splitting into 6 segments.",
        result: "FAILURE. Local segment decryption failed to yield continuous substrings."
    },
    {
        num: 8,
        name: "Shifted Running Keys",
        objective: "Exhaustively test every single possible starting offset of the K1, K2, and K3 plaintexts acting as key material.",
        result: "FAILURE. All offsets mathematically eliminated."
    },
    {
        num: 9,
        name: "External Text Running Key",
        objective: "Extract full historical text of Howard Carter's diary and use as a massive offset running key.",
        result: "FAILURE. Historical diary did not unlock plaintexts at any offset."
    },
    {
        num: 10,
        name: "Fractionated Polygraphic Solvers",
        objective: "Test if K4 breaks characters into coordinates before substitution (Bifid/Playfair) to flatten the IoC.",
        result: "FAILURE. Cipher mechanism remains resistant to positional diffusion."
    },
    {
        num: 11,
        name: "Deluxe Suite & Mojo Acceleration",
        objective: "Shatter Python computational ceilings via SIMD-vectorized Mojo structs on WSL.",
        result: "FAILURE. Million-key compiled sweeps processed fast, but did not crack K4."
    },
    {
        num: 12,
        name: "Massive Dictionary Fractionation Sweep",
        objective: "Combine Bifid matrices with 9,510 unified Custom Keys against 12 transposition periods (114,120 permutations).",
        result: "FAILURE. Swept 84 Million algorithmic matrix calculations simultaneously. Zero decipherments synthesized."
    },
    {
        num: 13,
        name: "Native Windows GPU Acceleration (OpenCL)",
        objective: "Target the AMD Radeon Graphic Card within Windows to natively run OpenCL C kernels.",
        result: "FAILURE. Processed 4,200,000,000 distinct permutations in 540 seconds (7.77M/sec). 4.2 Billion keys produced no plaintexts."
    }
];

document.addEventListener("DOMContentLoaded", () => {
    // Populate the Assault Log Timeline
    const timelineContainer = document.getElementById("timeline-container");
    
    strategies.forEach(strategy => {
        const item = document.createElement("div");
        item.className = "timeline-item";
        
        // Stagger entrance animations
        item.style.opacity = "0";
        item.style.transform = "translateY(20px)";
        item.style.transition = "all 0.6s cubic-bezier(0.16, 1, 0.3, 1)";
        
        item.innerHTML = `
            <div class="strategy-num">STRATEGY ${String(strategy.num).padStart(2, '0')}</div>
            <h3>${strategy.name}</h3>
            <p><strong>Objective:</strong> ${strategy.objective}</p>
            <div class="timeline-result">${strategy.result}</div>
        `;
        timelineContainer.appendChild(item);
    });

    // Intersection Observer for Scroll Animations
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries, obs) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = "1";
                entry.target.style.transform = "translateY(0)";
                
                // If this is the analytics section, trigger the bar widths
                if (entry.target.id === 'analytics') {
                    setTimeout(() => {
                        const bars = document.querySelectorAll('.bar');
                        // Widths are hardcoded inline in HTML for initial 0, let's trigger
                        // Actually, I put styles inline. Let's just let css transition handle it.
                    }, 200);
                }
                
                obs.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Observe timeline items and sections
    document.querySelectorAll('.timeline-item, .section').forEach(el => {
        if (!el.id || el.id !== 'hero-panel') {
            el.style.opacity = "0";
            el.style.transform = "translateY(20px)";
            el.style.transition = "opacity 0.8s ease-out, transform 0.8s ease-out";
            observer.observe(el);
        }
    });
});
