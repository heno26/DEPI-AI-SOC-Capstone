"use strict";

const $ = id => document.getElementById(id);

const state = {
    page: "overview",
    health: {},
    incidents: {},
    lifecycle: {},
    decisions: {},
    reviews: {},
    reports: {},
    reportCenter: {},
    timeline: {},
    aiStatus: {},
    aiAssessments: [],
    aiSelected: null,
    aiBusy: false,
    aiError: null
};

const esc = value => String(value ?? "N/A")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const arr = value => Array.isArray(value) ? value : [];

const pretty = value => JSON.stringify(value, null, 2);

async function api(path) {
    const response = await fetch("/api/" + path, {
        cache: "no-store"
    });

    if (!response.ok) {
        throw new Error(path + ": HTTP " + response.status);
    }

    return response.json();
}



async function apiPost(path, payload) {

    const response = await fetch("/api/" + path, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        cache: "no-store",
        body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || "Request failed");
    }

    return data;
}


function metric(label, value) {
    return `
        <div class="metric">
            <small>${esc(label)}</small>
            <strong>${esc(value)}</strong>
        </div>`;
}

function badge(value) {
    const text = String(value ?? "Unknown");
    const lower = text.toLowerCase();

    let color = "";

    if (/critical|high|blocked|offline|rejected/.test(lower)) {
        color = "bad";
    } else if (/pending|partial|medium|review|required|deferred/.test(lower)) {
        color = "warn";
    } else if (/complete|approved|online|low|done|corrected/.test(lower)) {
        color = "good";
    }

    return `<span class="badge ${color}">${esc(text)}</span>`;
}

function panel(title, content) {
    return `
        <section class="panel">
            <h2>${esc(title)}</h2>
            ${content}
        </section>`;
}

function table(headers, rows) {
    return `
        <table>
            <thead>
                <tr>${headers.map(h => `<th>${esc(h)}</th>`).join("")}</tr>
            </thead>
            <tbody>
                ${rows.length ? rows.join("") :
                `<tr><td colspan="${headers.length}">No records available</td></tr>`}
            </tbody>
        </table>`;
}

function row(cells) {
    return `<tr>${cells.map(c => `<td>${c}</td>`).join("")}</tr>`;
}

function detail(title, data) {
    $("dialog-title").textContent = title;
    $("dialog-content").innerHTML =
        `<pre>${esc(typeof data === "string" ? data : pretty(data))}</pre>`;

    if (!$("detail-dialog").open) {
        $("detail-dialog").showModal();
    }
}

function button(label, type, index) {
    return `<button data-detail="${esc(type)}"
                    data-index="${esc(index)}">
                    ${esc(label)}
            </button>`;
}

function caseList() {
    return arr(state.incidents.cases);
}

function caseRows(cases) {
    return cases.map(c => row([
        esc(c.case_id),
        esc(c.title),
        esc(c.domain),
        badge(c.ai?.severity),
        badge(c.ai?.qa_status),
        esc(c.playbook),
        button("Investigate", "case", caseList().indexOf(c))
    ]));
}

function attackStages() {
    return arr(state.incidents.scenario?.stages).map(s => `
        <div class="stage">
            <span class="stage-id">${esc(s.stage_id)}</span>
            <div>
                <strong>${esc(s.name)}</strong>
                <div class="muted">
                    ${esc(s.domain)} |
                    ${arr(s.case_ids).length} cases
                </div>
            </div>
        </div>
    `).join("");
}

function overview() {
    const i = state.incidents;
    const l = state.lifecycle;

    return `
        <div class="metrics">
            ${metric("Security Cases", caseList().length)}
            ${metric("Timeline Events", i.timeline_events)}
            ${metric("Observables", arr(i.observables).length)}
            ${metric("Response Items", arr(l.items).length)}
            ${metric("Analyst Decisions", state.decisions.count)}
            ${metric("Final Reports", state.reports.count)}
        </div>

        <div class="grid-two">
            ${panel("Attack Chain", attackStages())}

            ${panel("Incident Response Lifecycle",
                arr(l.phases).map(p => `
                    <div class="stage">
                        <div style="flex:1">
                            <strong>${esc(p.name)}</strong>
                            <div class="muted">${esc(p.detail)}</div>
                        </div>
                        ${badge(p.status)}
                    </div>
                `).join("")
            )}
        </div>

        ${panel("Security Cases",
            table(
                ["Case ID", "Description", "Domain", "Severity",
                 "QA Status", "Playbook", "Action"],
                caseRows(caseList())
            )
        )}
    `;
}

function casesPage() {
    const domains = [...new Set(caseList().map(c => c.domain))]
        .filter(Boolean).sort();

    return panel("Security Alerts & Cases", `
        <div class="toolbar">
            <input id="case-search"
                   placeholder="Search case ID, description, domain...">

            <select id="domain-filter">
                <option value="">All Domains</option>
                ${domains.map(d =>
                    `<option value="${esc(d)}">${esc(d)}</option>`
                ).join("")}
            </select>

            <select id="severity-filter">
                <option value="">All Severities</option>
                <option>Critical</option>
                <option>High</option>
                <option>Medium</option>
                <option>Low</option>
            </select>
        </div>

        <div id="case-table">
            ${table(
                ["Case ID", "Description", "Domain", "Severity",
                 "QA Status", "Playbook", "Action"],
                caseRows(caseList())
            )}
        </div>
    `);
}

function filterCases() {
    const query = $("case-search").value.toLowerCase();
    const domain = $("domain-filter").value;
    const severity = $("severity-filter").value.toLowerCase();

    const filtered = caseList().filter(c => {
        const text = [
            c.case_id, c.title, c.domain, c.playbook
        ].join(" ").toLowerCase();

        return text.includes(query) &&
            (!domain || c.domain === domain) &&
            (!severity ||
             String(c.ai?.severity).toLowerCase() === severity);
    });

    $("case-table").innerHTML = table(
        ["Case ID", "Description", "Domain", "Severity",
         "QA Status", "Playbook", "Action"],
        caseRows(filtered)
    );
}

function investigations() {
    return panel("Multi-Stage Incident Investigation",
        arr(state.incidents.scenario?.stages).map(s => `
            <div class="stage">
                <span class="stage-id">${esc(s.stage_id)}</span>
                <div style="flex:1">
                    <strong>${esc(s.name)}</strong>
                    <p>${esc(s.question_for_analysts)}</p>
                    <small class="muted">
                        ${esc(arr(s.case_ids).join(", "))}
                    </small>
                </div>
                ${button("View Stage", "stage",
                    arr(state.incidents.scenario.stages).indexOf(s))}
            </div>
        `).join("")
    );
}

function timeline() {
    const events = arr(state.timeline.events);

    const domains = Object.keys(
        state.timeline.statistics?.domains || {}
    );

    const cases = Object.keys(
        state.timeline.statistics?.cases || {}
    );

    const stages = Object.keys(
        state.timeline.statistics?.stages || {}
    );

    const qualities = Object.keys(
        state.timeline.statistics?.timestamp_quality || {}
    );

    const options = (items, label) =>
        `<option value="">${label}</option>` +
        items.map(item =>
            `<option value="${esc(item)}">${esc(item)}</option>`
        ).join("");

    return panel("Incident Timeline", `
        <p>Original dataset timestamps are preserved.</p>

        <p class="muted">
            Scenario stages do not establish observed causal links.
            Timeline records are read-only.
        </p>

        <div class="metrics">
            ${metric("Total Events", state.timeline.count ?? 0)}
            ${metric("Domains", domains.length)}
            ${metric("Unique Cases", cases.length)}
            ${metric("Attack Stages", stages.length)}
        </div>

        <div class="metrics">
            ${Object.entries(
                state.timeline.statistics?.domains || {}
            ).map(([name, count]) =>
                metric(name + " Events", count)
            ).join("")}
        </div>

        <h3>Timeline Event Explorer</h3>

        <div class="toolbar">
            <input
                id="timeline-search"
                type="search"
                placeholder="Search event, reference, case ID, summary..."
            >

            <select id="timeline-domain">
                ${options(domains, "All Domains")}
            </select>

            <select id="timeline-case">
                ${options(cases, "All Cases")}
            </select>

            <select id="timeline-stage">
                ${options(stages, "All Stages")}
            </select>

            <select id="timeline-quality">
                ${options(qualities, "All Timestamp Qualities")}
            </select>
        </div>

        <p id="timeline-results" class="muted">
            Showing ${events.length} events
        </p>

        <div id="timeline-table"></div>

        <h3>Attack Scenario Stages</h3>

        ${attackStages()}
    `);
}


function parseTimelineTimestamp(event) {

    const quality = event.ts_quality || "";
    const raw = (event.ts_original || "").trim();

    // Only timestamps with an explicit timezone are sortable.
    if (![
        "original_utc",
        "original_utc_minute",
        "original_with_offset"
    ].includes(quality)) {
        return null;
    }

    // ISO-8601 with explicit Z or UTC offset.
    const iso = Date.parse(raw);

    if (Number.isFinite(iso) &&
        /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw)) {
        return iso;
    }

    // Apache timestamp: 13/Oct/2024:09:38:07 +0000
    const apache = raw.match(
        /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$/
    );

    if (apache) {

        const months = {
            Jan: 0, Feb: 1, Mar: 2, Apr: 3,
            May: 4, Jun: 5, Jul: 6, Aug: 7,
            Sep: 8, Oct: 9, Nov: 10, Dec: 11
        };

        const month = months[
            apache[2].charAt(0).toUpperCase() +
            apache[2].slice(1).toLowerCase()
        ];

        if (month === undefined) return null;

        const normalized =
            `${apache[3]}-${String(month + 1).padStart(2, "0")}-${apache[1]}T` +
            `${apache[4]}:${apache[5]}:${apache[6]}${apache[7].slice(0, 3)}:${apache[7].slice(3)}`;

        const parsed = Date.parse(normalized);

        return Number.isFinite(parsed) ? parsed : null;
    }

    return null;
}

function filterTimeline() {
    const events = arr(state.timeline.events);

    const search = $("timeline-search").value
        .trim().toLowerCase();

    const domain = $("timeline-domain").value;
    const caseId = $("timeline-case").value;
    const stage = $("timeline-stage").value;
    const quality = $("timeline-quality").value;

    const filtered = events.filter(event => {

        const searchable = [
            event.seq,
            event.stage_id,
            event.stage,
            event.domain,
            event.case_id,
            event.ts_original,
            event.ts_quality,
            event.summary,
            event.ref,
            event.source
        ].join(" ").toLowerCase();

        return searchable.includes(search) &&
            (!domain || event.domain === domain) &&
            (!caseId || event.case_id === caseId) &&
            (!stage || event.stage_id === stage) &&
            (!quality || event.ts_quality === quality);
    });

    // Sort trusted timestamps chronologically.
    // Preserve original order for unknown timestamps and equal timestamps.

    const sortable = filtered.map((event, index) => ({
        event,
        index,
        timestamp: parseTimelineTimestamp(event)
    }));

    sortable.sort((a, b) => {

        if (a.timestamp === null && b.timestamp === null) {
            return a.index - b.index;
        }

        if (a.timestamp === null) return 1;
        if (b.timestamp === null) return -1;

        return (a.timestamp - b.timestamp) ||
            (a.index - b.index);
    });

    filtered.splice(
        0,
        filtered.length,
        ...sortable.map(item => item.event)
    );
    $("timeline-results").textContent =
        `Showing ${filtered.length} of ${events.length} events`;

    $("timeline-table").innerHTML = table(
        [
            "Seq",
            "Timestamp (Original)",
            "Case ID",
            "Domain",
            "Stage",
            "Timestamp Quality",
            "Reference",
            "Details"
        ],
        filtered.map(event => {
            const index = events.indexOf(event);

            return row([
                esc(event.seq),
                esc(event.ts_original),
                esc(event.case_id),
                esc(event.domain),
                esc(event.stage_id),
                badge(event.ts_quality),
                esc(event.ref),
                button("View Event", "timeline-event", index)
            ]);
        })
    );
}

function aiPage() {
    const cases = caseList();
    const assessments = arr(state.aiAssessments);
    const selectedCaseId =
        state.aiSelectedCaseId || state.aiSelected?.case_id || "";

    const options = cases.map(c => `
        <option value="${esc(c.case_id)}" ${selectedCaseId === c.case_id ? "selected" : ""}>
            ${esc(c.case_id)} â€” ${esc(c.title)}
        </option>
    `).join("");

    const selected = state.aiSelected;

    const result = selected?.assessment || null;

    const history = assessments.map((item, index) => `
        <div class="stage">
            <div style="flex:1;min-width:0">
                <strong>${esc(item.case_id)}</strong>
                <div class="muted">
                    ${esc(item.generated_at_utc)}
                </div>
                <div>
                    ${badge(item.assessment?.severity)}
                    ${badge(item.qa_status)}
                </div>
            </div>

            <button data-ai-view="${index}">
                View
            </button>
        </div>
    `).join("");

    const resultHTML = result ? `
        <div class="metrics">
            ${metric("Severity", result.severity)}
            ${metric("Confidence", result.confidence)}
            ${metric("Model", selected.model)}
            ${metric("Human Validation",
                result.human_validation_required ? "Required" : "Not Required")}
        </div>

        ${panel("Executive Summary",
            `<p>${esc(result.executive_summary)}</p>`
        )}

        ${panel("Verdict",
            `<p>${esc(result.verdict)}</p>`
        )}

        ${panel("Observed Facts",
            arr(result.observed_facts).map(x =>
                `<div class="stage">${esc(x)}</div>`
            ).join("") || "None"
        )}

        ${panel("Analytical Findings",
            arr(result.analytical_findings).map(x =>
                `<div class="stage">${esc(x)}</div>`
            ).join("") || "None"
        )}

        ${panel("Hypotheses",
            arr(result.hypotheses).map(x =>
                `<div class="stage">${esc(x)}</div>`
            ).join("") || "None"
        )}

        ${panel("MITRE ATT&CK Mapping",
            arr(result.mitre_mapping).map(x => `
                <div class="stage">
                    <strong>${esc(x.technique)}</strong>
                    â€” ${esc(x.name)}
                    â€” ${esc(x.tactic)}
                </div>
            `).join("") || "None"
        )}

        ${panel("Evidence Gaps",
            arr(result.evidence_gaps).map(x =>
                `<div class="stage">${esc(x)}</div>`
            ).join("") || "None"
        )}

        ${panel("Recommended Actions",
            arr(result.recommended_actions).map((x, i) =>
                `<div class="stage">${i + 1}. ${esc(x)}</div>`
            ).join("") || "None"
        )}

        ${panel("Prohibited Assumptions",
            arr(result.prohibited_assumptions).map(x =>
                `<div class="stage">${esc(x)}</div>`
            ).join("") || "None"
        )}

        ${panel("Evidence Integrity",
            arr(selected.evidence_integrity).map(x => `
                <div class="stage">
                    ${esc(x.path)}
                    ${badge(x.hash_verified ? "HASH VERIFIED" :
                        x.exists ? "HASH MISMATCH" : "MISSING")}
                </div>
            `).join("") || "No evidence records"
        )}

        ${panel("Assessment Metadata",
            `<pre>${esc(pretty({
                assessment_id: selected.assessment_id,
                generated_at_utc: selected.generated_at_utc,
                model: selected.model,
                scenario_id: selected.scenario_id,
                qa_status: selected.qa_status,
                response_execution: selected.response_execution
            }))}</pre>`
        )}

        ${panel("Complete Assessment JSON",
            `<details>
                <summary>View full assessment</summary>
                <pre>${esc(pretty(selected))}</pre>
            </details>`
        )}

    ` : `
        <p class="muted">
            Select a case and run an AI analysis to view the results here.
        </p>
    `;

    return `
        <div class="metrics">
            ${metric("Available Cases", cases.length)}
            ${metric("Saved AI Assessments", assessments.length)}
            ${metric("Primary Model",
                state.aiStatus.primary_model || "Unavailable")}
            ${metric("AI Engine",
                state.aiStatus.connected ? "Online" : "Offline")}
        </div>

        ${panel("AI Analysis Engine", `
            <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
                <select id="ai-case-select" style="flex:1;min-width:260px">
                    <option value="">Select an incident case</option>
                    ${options}
                </select>

                <button id="ai-analyze-button"
                    ${state.aiBusy ? "disabled" : ""}>
                    ${state.aiBusy ? "Analyzing..." : "Analyze with Mistral 7B"}
                </button>
            </div>

            <p class="muted">
                Primary model:
                ${esc(state.aiStatus.primary_model)}
            </p>

            <p class="muted">
                Analysis is generated locally using Ollama.
                All response actions remain disabled.
            </p>

            ${state.aiError ? `
                <div class="stage">${esc(state.aiError)}</div>
            ` : ""}
        `)}

        ${panel("AI Analysis Result", resultHTML)}

        ${panel("Saved Analysis History", `
            ${history || `
                <p class="muted">No saved assessments available.</p>
            `}
        `)}
    `;
}

async function refreshAIData() {
    const [status, history] = await Promise.all([
        api("ai/status"),
        api("ai/assessments")
    ]);

    state.aiStatus = status;
    state.aiAssessments = arr(history.assessments);

    return history;
}

async function runAIAnalysis() {
    if (state.aiBusy) return;

    const caseId = $("ai-case-select")?.value;

    if (!caseId) {
        alert("Please select an incident case first.");
        return;
    }

    state.aiSelectedCaseId = caseId;
    state.aiBusy = true;
    state.aiError = null;
    render();

    try {
        const response = await fetch("/api/ai/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            cache: "no-store",
            body: JSON.stringify({
                case_id: caseId
            })
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "AI analysis failed");
        }

        await refreshAIData();

        state.aiSelected = data.result;

        state.aiError = null;

    } catch (error) {

        state.aiError = error.message;

    } finally {

        state.aiBusy = false;

        if (state.page === "ai") {
            render();
        }
    }
}

function mitre() {
    const rows = caseList().flatMap(c =>
        arr(c.attack).map(a => row([
            esc(c.case_id),
            esc(a.technique),
            esc(a.name),
            esc(a.tactic),
            badge(a.confidence),
            esc(a.basis)
        ]))
    );

    return panel("MITRE ATT&CK Technique Mapping",
        table(
            ["Case", "Technique", "Name", "Tactic",
             "Confidence", "Evidence Basis"],
            rows
        )
    );
}

function soar() {
    const rows = caseList().flatMap(c =>
        arr(c.tickets).map(t => row([
            esc(c.case_id),
            esc(t.playbook_id),
            esc(t.tier),
            badge(t.review_status),
            esc(arr(t.proposed_actions).join(", ")),
            button("View Case", "case", caseList().indexOf(c))
        ]))
    );

    return panel("SOAR Playbooks & Historical Tickets",
        table(
            ["Case", "Playbook", "Tier", "Review",
             "Proposed Actions", "Details"],
            rows
        )
    );
}


function responsePage() {

    const items = arr(state.lifecycle.items);

    const selectedCase = state.responseCase || "";

    const cases = [...new Set(
        items.map(item => item.case_id).filter(Boolean)
    )];

    const filtered = items.filter(item =>
        !selectedCase || item.case_id === selectedCase
    );

    const rows = filtered.map(item => {

        const prohibited =
            item.decision === "prohibited_by_design" ||
            item.phase === "prohibited";

        return `
            <div class="stage"
                 style="display:block;margin-bottom:12px">

                <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap">

                    <strong>${esc(item.case_id)}</strong>

                    ${badge(item.decision)}
                </div>

                <p>
                    <strong>Phase:</strong>
                    ${esc(item.phase)}
                    &nbsp; | &nbsp;
                    <strong>Tier:</strong>
                    ${esc(item.tier)}
                </p>

                <p>${esc(item.action)}</p>

                <small class="muted">
                    Item ID: ${esc(item.item_id)}
                </small>

                <p class="muted">
                    ${esc(item.basis)}
                </p>

                <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">

                    <button
                        data-decision="approved"
                        data-item="${esc(item.item_id)}"
                        ${prohibited ? "disabled" : ""}>
                        Approve
                    </button>

                    <button
                        data-decision="rejected"
                        data-item="${esc(item.item_id)}"
                        ${prohibited ? "disabled" : ""}>
                        Reject
                    </button>

                    <button
                        data-decision="deferred"
                        data-item="${esc(item.item_id)}"
                        ${prohibited ? "disabled" : ""}>
                        Defer
                    </button>

                </div>

                ${prohibited ? `
                    <p class="muted">
                        Prohibited by design ? analyst approval unavailable.
                    </p>
                ` : ""}

            </div>
        `;
    }).join("");

    return `
        <div class="metrics">

            ${metric("Response Items", items.length)}

            ${metric("Recorded Decisions",
                state.decisions.count || 0)}

            ${metric("Real Actions Executed", 0)}

        </div>

        ${panel("Decision Center", `

            <div class="toolbar">

                <select id="response-case-filter">

                    <option value="">All Cases</option>

                    ${cases.map(id => `
                        <option value="${esc(id)}"
                            ${selectedCase === id ? "selected" : ""}>
                            ${esc(id)}
                        </option>
                    `).join("")}

                </select>

                <input
                    id="decision-analyst"
                    placeholder="Analyst name"
                    maxlength="100"
                />

            </div>

            <textarea
                id="decision-note"
                placeholder="Decision justification / analyst notes"
                maxlength="2000"
                rows="3"
                style="width:100%;margin:12px 0"
            ></textarea>

            <p class="muted">
                Decisions are recorded for human audit.
                No real response action is executed.
            </p>

            <div id="decision-message"></div>

            ${rows || `
                <p class="muted">
                    No response items available.
                </p>
            `}

        `)}

        ${panel("Existing Decision Records",

            table(
                ["Timestamp", "Item", "Decision", "Analyst", "Method"],

                arr(state.decisions.records).map(r => row([
                    esc(r.ts_utc),
                    esc(r.item_id),
                    badge(r.decision),
                    esc(r.analyst),
                    esc(r.via)
                ]))
            )
        )}

        ${panel("Decision Safety",

            `<p>
                Approval records analyst authorization only.
                No firewall, endpoint, account or network changes
                are performed by this interface.
            </p>`
        )}

    `;
}

function evidence() {
    return panel("Evidence & Observables",
        table(
            ["Type", "Value", "Cases", "Scope", "Reputation"],
            arr(state.incidents.observables).map(o => row([
                esc(o.type),
                esc(o.value),
                esc(arr(o.cases).join(", ")),
                esc(o.scope),
                esc(o.reputation)
            ]))
        )
    );
}

function reportsPage() {
    return panel("Final Capstone Reports",
        table(
            ["Report", "Size", "Preview", "Download"],
            arr(state.reports.reports).map((r, index) => row([
                esc(r.filename),
                esc((r.size_bytes / 1024).toFixed(1) + " KB"),
                button("Read Report", "report", index),
                `<a href="/api/reports/${encodeURIComponent(r.filename)}/download"
                    style="color:var(--cyan)">Download</a>`
            ]))
        )
    );
}

// V2_11_REPORT_CENTER_FRONTEND

function reportCenterPage() {

    const records = arr(state.reportCenter.records);

    const categories = state.reportCenter.categories || {};

    const options = Object.keys(categories).map(category =>
        `<option value="${esc(category)}">${esc(category)} (${categories[category]})</option>`
    ).join("");

    const rows = records.map((r,index) => row([
        esc(r.category),
        esc(r.filename),
        esc((r.size_bytes / 1024).toFixed(1) + " KB"),
        esc(new Date(r.modified_utc).toLocaleString()),
        `<button data-report-center-preview="${index}">Preview</button>`,
        `<a href="${esc(r.download_url)}" download>Download</a>`
    ])).join("");

    return `
        <div class="metrics">
            ${metric("Total Files", records.length)}
            ${metric("Categories", Object.keys(categories).length)}
            ${metric("Read Only", "Enabled")}
        </div>

        ${panel("Unified Report Center", `
            <div class="toolbar">
                <input
                    id="report-center-search"
                    placeholder="Search reports, assessments and drafts..."
                >

                <select id="report-center-category">
                    <option value="">All Categories</option>
                    ${options}
                </select>
            </div>

            <div id="report-center-table">
                <table>
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Filename</th>
                            <th>Size</th>
                            <th>Modified</th>
                            <th>Preview</th>
                            <th>Download</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows}
                    </tbody>
                </table>
            </div>

            <p class="muted">
                Read-only access. Original evidence and source files
                are never modified by this interface.
            </p>
        `)}
    `;
}

function filterReportCenter() {

    const search = $("report-center-search").value.toLowerCase();

    const category = $("report-center-category").value;

    document.querySelectorAll(
        "#report-center-table tbody tr"
    ).forEach(tr => {

        const text = tr.textContent.toLowerCase();

        const rowCategory = tr.cells[0]?.textContent.trim();

        tr.hidden =
            !text.includes(search) ||
            (category !== "" && rowCategory !== category);
    });
}

// =====================================================
// V2_12_SOC_ANALYTICS
// Evidence-driven SOC Analytics Dashboard
// =====================================================

function analyticsBarList(title, groups) {

    const sorted = groups
        .filter(item => item.count > 0)
        .sort((a, b) => b.count - a.count);

    const max = Math.max(
        1,
        ...sorted.map(item => item.count)
    );

    return panel(title, sorted.length ? sorted.map(item => `
        <div class="analytics-bar-row">
            <div class="analytics-bar-label">
                <span>${esc(item.name)}</span>
                <strong>${item.count}</strong>
            </div>
            <div class="analytics-bar-track">
                <div class="analytics-bar-fill"
                     style="width:${(item.count / max) * 100}%">
                </div>
            </div>
        </div>
    `).join("") : `
        <p class="muted">No classified data available.</p>
    `);
}


function analyticsGroup(items, selector) {

    const counts = {};

    items.forEach(item => {

        const key = selector(item) || "Unclassified";

        counts[key] = (counts[key] || 0) + 1;

    });

    return Object.entries(counts).map(([name, count]) => ({
        name,
        count
    }));
}


function analyticsPage() {

    const cases = arr(state.incidents.cases);
    const events = arr(state.timeline.events);
    const lifecycle = arr(state.lifecycle.items);
    const decisions = arr(state.decisions.records);
    const reviews = arr(state.reviews.records);
    const assessments = arr(state.aiAssessments);

    const severity = analyticsGroup(
        cases,
        c => c.ai?.severity
    );

    const domains = analyticsGroup(
        cases,
        c => c.domain
    );

    const stages = analyticsGroup(
        events,
        e => e.stage
    );

    const decisionGroups = analyticsGroup(
        decisions,
        d => d.decision
    );

    const reviewGroups = analyticsGroup(
        reviews,
        r => r.status
    );

    const humanGroups = analyticsGroup(
        cases,
        c => c.human_review?.status
    );

    const lifecycleGroups = analyticsGroup(
        lifecycle,
        item => item.phase
    );

    const classified = cases.filter(
        c => c.ai?.severity
    ).length;

    const unclassified = cases.length - classified;

    return `

        <div class="metrics">

            ${metric("Total Incidents", cases.length)}

            ${metric("Timeline Events", events.length)}

            ${metric("Response Items", lifecycle.length)}

            ${metric("Analyst Decisions", decisions.length)}

            ${metric("AI Assessments", assessments.length)}

            ${metric("AI Draft Reviews", reviews.length)}

        </div>

        ${panel("SOC Analytics Overview", `

            <div class="analytics-summary">

                <div class="stage">
                    <span>Classified Incidents</span>
                    <strong>${classified}</strong>
                </div>

                <div class="stage">
                    <span>Unclassified Incidents</span>
                    <strong>${unclassified}</strong>
                </div>

                <div class="stage">
                    <span>Evidence Events</span>
                    <strong>${events.length}</strong>
                </div>

                <div class="stage">
                    <span>Real Response Execution</span>
                    <strong>DISABLED</strong>
                </div>

            </div>

        `)}

        <div class="analytics-grid">

            ${analyticsBarList(
                "Incident Severity Distribution",
                severity
            )}

            ${analyticsBarList(
                "Incident Distribution by Domain",
                domains
            )}

            ${analyticsBarList(
                "Attack Timeline Distribution",
                stages
            )}

            ${analyticsBarList(
                "Analyst Decision Distribution",
                decisionGroups
            )}

            ${analyticsBarList(
                "AI Review Results",
                reviewGroups
            )}

            ${analyticsBarList(
                "Human Validation Status",
                humanGroups
            )}

            ${analyticsBarList(
                "Response Lifecycle Phases",
                lifecycleGroups
            )}

        </div>

        ${panel("Analytics Data Integrity", `

            <div class="stage">
                <span>Source</span>
                <strong>Project Dataset</strong>
            </div>

            <div class="stage">
                <span>Original Evidence</span>
                <strong>READ ONLY</strong>
            </div>

            <div class="stage">
                <span>Calculation</span>
                <strong>Local Data Aggregation</strong>
            </div>

            <div class="stage">
                <span>External Dependencies</span>
                <strong>NONE</strong>
            </div>

            <div class="stage">
                <span>Execution Mode</span>
                <strong>SIMULATION ONLY</strong>
            </div>

            <p class="muted">
                All figures are calculated from the currently loaded
                project records. Unclassified records are preserved
                and reported separately.
            </p>

        `)}

    `;
}

function audit() {
    return panel("Analyst Decision Audit Log",
        table(
            ["Timestamp", "Analyst", "Item", "Decision", "Method"],
            arr(state.decisions.records).map(r => row([
                esc(r.ts_utc),
                esc(r.analyst),
                esc(r.item_id),
                badge(r.decision),
                esc(r.via)
            ]))
        )
    );
}

function healthPage() {
    return `
        <div class="metrics">
            ${metric("Backend", state.health.backend)}
            ${metric("Project Data",
                state.health.data_ready ? "READY" : "ERROR")}
            ${metric("Ollama",
                state.health.ollama?.connected ? "ONLINE" : "OFFLINE")}
        </div>

        ${panel("Project Integration Status",
            Object.entries(state.health.weeks || {}).map(([k,v]) => `
                <div class="stage">
                    <strong style="flex:1">${esc(k)}</strong>
                    ${badge(v ? "ONLINE" : "MISSING")}
                </div>
            `).join("")
        )}

        ${panel("Backend Health Details",
            `<pre>${esc(pretty(state.health))}</pre>`
        )}
    `;
}

function settings() {
    return panel("System Configuration", `
        <div class="stage">Deployment: Local workstation</div>
        <div class="stage">Mode: SIMULATION_ONLY</div>
        <div class="stage">Original Evidence: READ ONLY</div>
        <div class="stage">Real Response Execution: DISABLED</div>
        <div class="stage">External CDN: NOT REQUIRED</div>
        <div class="stage">Human Approval: REQUIRED</div>
        <div class="stage">Version: 2.0.0-dev</div>
    `);
}

const pages = {
    overview,
    cases: casesPage,
    investigations,
    timeline,
    ai: aiPage,
    mitre,
    soar,
    response: responsePage,
    evidence,
    reports: reportsPage,
    reportCenter: reportCenterPage,
    analytics: analyticsPage,
    audit,
    health: healthPage,
    settings
};

function render() {
    $("page-content").innerHTML = pages[state.page]();

    if (state.page === "reportCenter") {

        $("report-center-search").addEventListener(
            "input", filterReportCenter
        );

        $("report-center-category").addEventListener(
            "change", filterReportCenter
        );
    }

    if (state.page === "cases") {
        $("case-search").addEventListener("input", filterCases);
        $("domain-filter").addEventListener("change", filterCases);
        $("severity-filter").addEventListener("change", filterCases);
    }

    if (state.page === "timeline") {
        [
            "timeline-search",
            "timeline-domain",
            "timeline-case",
            "timeline-stage",
            "timeline-quality"
        ].forEach(id => {
            $(id).addEventListener(
                id === "timeline-search" ? "input" : "change",
                filterTimeline
            );
        });

        filterTimeline();
    }
}

async function loadData() {
    $("refresh-button").disabled = true;

    try {
        const results = await Promise.all([
            api("health"),
            api("incidents"),
            api("lifecycle"),
            api("decisions"),
            api("ai-reviews"),
            api("reports"),
            api("report-center"),
            api("timeline")
        ]);

        [
            state.health,
            state.incidents,
            state.lifecycle,
            state.decisions,
            state.reviews,
            state.reports,
            state.reportCenter,
            state.timeline
        ] = results;

        await refreshAIData();
        $("backend-status").textContent = "Backend Online";
        $("backend-status").className = "badge good";

        const connected = state.health.ollama?.connected;

        $("ollama-status").textContent =
            connected ? "Ollama Online" : "Ollama Offline";

        $("ollama-status").className =
            connected ? "badge good" : "badge warn";

        $("last-update").textContent =
            "Last refresh: " + new Date().toLocaleString();

        render();

    } catch (error) {
        $("backend-status").textContent = "Data Error";
        $("backend-status").className = "badge bad";

        $("page-content").innerHTML =
            `<div class="panel bad">${esc(error.message)}</div>`;

    } finally {
        $("refresh-button").disabled = false;
    }
}

document.querySelectorAll(".nav").forEach(nav => {
    nav.addEventListener("click", () => {
        document.querySelectorAll(".nav").forEach(n =>
            n.classList.remove("active")
        );

        nav.classList.add("active");
        state.page = nav.dataset.page;

        $("page-title").textContent = nav.textContent;
        render();
    });
});

document.addEventListener("click", async event => {
    const target = event.target.closest("[data-detail]");
    if (!target) return;

    const index = Number(target.dataset.index);

    try {
        switch (target.dataset.detail) {
            case "case":
                openInvestigation(caseList()[index]);
                break;

            case "stage":
                detail("Attack Stage",
                    state.incidents.scenario.stages[index]);
                break;

            case "timeline-event":
                detail("Timeline Event",
                    state.timeline.events[index]);
                break;

            case "response":
                detail("Response Decision",
                    state.lifecycle.items[index]);
                break;

            case "report": {
                const file = state.reports.reports[index].filename;
                const report = await api(
                    "reports/" + encodeURIComponent(file)
                );
                detail(report.filename, report.content);
                break;
            }
        }
    } catch (error) {
        detail("Request Error", error.message);
    }
});

document.addEventListener("click", async event => {

    const analyze = event.target.closest("#ai-analyze-button");

    if (analyze) {
        await runAIAnalysis();
        return;
    }

    const view = event.target.closest("[data-ai-view]");

    if (view) {

        const index = Number(view.dataset.aiView);

        state.aiSelected = state.aiAssessments[index] || null;

        state.aiError = null;

        render();
    }
});
$("close-dialog").addEventListener("click", () =>
    $("detail-dialog").close()
);



// =====================================================
// DEPI_P5_DECISION_CENTER_V1
// =====================================================

document.addEventListener("change", event => {

    if (event.target.id === "response-case-filter") {

        state.responseCase = event.target.value;
        render();

    }

});

document.addEventListener("click", async event => {

    const button = event.target.closest("[data-decision]");

    if (!button) return;

    const itemId = button.dataset.item;
    const decision = button.dataset.decision;

    const analyst = $("decision-analyst")?.value.trim();
    const note = $("decision-note")?.value.trim() || "";

    if (!analyst) {
        alert("Enter the analyst name first.");
        return;
    }

    const labels = {
        approved: "APPROVE",
        rejected: "REJECT",
        deferred: "DEFER"
    };

    if (!confirm(
        "Confirm " + labels[decision] +
        " for this response item?"
    )) return;

    button.disabled = true;

    try {

        await apiPost("decisions", {
            item_id: itemId,
            decision: decision,
            analyst: analyst,
            note: note
        });

        const [lifecycle, decisions] = await Promise.all([
            api("lifecycle"),
            api("decisions")
        ]);

        state.lifecycle = lifecycle;
        state.decisions = decisions;

        render();

        alert("Decision saved successfully.");

    } catch (error) {

        alert("Decision failed: " + error.message);
        button.disabled = false;

    }

});


// V2-11 Report Center Preview Handler

document.addEventListener("click", async event => {

    const target = event.target.closest(
        "[data-report-center-preview]"
    );

    if (!target) return;

    const index = Number(target.dataset.reportCenterPreview);

    const item = arr(state.reportCenter.records)[index];

    if (!item) return;

    target.disabled = true;

    try {

        const response = await fetch(item.preview_url, {
            cache: "no-store"
        });

        const payload = await response.json();

        if (!response.ok) {
            throw new Error(payload.error || "Preview failed");
        }

        detail(item.filename, payload.content);

    } catch (error) {

        detail("Preview Error", error.message);

    } finally {

        target.disabled = false;

    }
});
$("refresh-button").addEventListener("click", loadData);

loadData();

function investigationFields(data) {
    if (!data || typeof data !== "object") {
        return `<p>${esc(data)}</p>`;
    }

    const entries = Object.entries(data);

    if (!entries.length) {
        return `<p class="muted">No recorded data.</p>`;
    }

    return `<div class="investigation-fields">
        ${entries.map(([key, value]) => `
            <div class="investigation-field">
                <small>${esc(key.replace(/_/g, " "))}</small>
                <div>${esc(
                    typeof value === "object"
                    ? pretty(value)
                    : value
                )}</div>
            </div>
        `).join("")}
    </div>`;
}

function investigationSection(title, content) {
    return `
        <section class="investigation-section">
            <h3>${esc(title)}</h3>
            ${content}
        </section>`;
}

function openInvestigation(c) {
    if (!c) {
        detail("Investigation Error", "Case not found.");
        return;
    }

    const decisions = arr(state.lifecycle.items)
        .filter(r => r.case_id === c.case_id);

    $("dialog-title").textContent =
        "Case Investigation | " + c.case_id;

    $("dialog-content").innerHTML = `

        <div class="investigation-hero">
            <span class="eyebrow">SECURITY INVESTIGATION</span>
            <h2>${esc(c.title)}</h2>

            <div class="investigation-tags">
                ${badge(c.domain)}
                ${badge(c.ai?.severity)}
                ${badge(c.ai?.qa_status)}
                ${badge(c.playbook)}
            </div>
        </div>

        <div class="metrics">
            ${metric("Events", arr(c.events).length)}
            ${metric("Evidence Files", arr(c.evidence_files).length)}
            ${metric("MITRE Techniques", arr(c.attack).length)}
            ${metric("Response Items", decisions.length)}
        </div>

        ${investigationSection("Detection Details",
            investigationFields({
                case_id: c.case_id,
                source: c.source_kind,
                domain: c.domain,
                detection_rule: c.detection_rule,
                dataset: c.dataset,
                playbook: c.playbook
            })
        )}

        ${investigationSection("Key Findings",
            investigationFields(c.facts || {})
        )}

        ${investigationSection("AI Triage",
            investigationFields(c.ai || {})
        )}

        ${investigationSection("MITRE ATT&CK",
            table(
                ["Technique", "Name", "Tactic", "Confidence", "Basis"],
                arr(c.attack).map(a => row([
                    esc(a.technique),
                    esc(a.name),
                    esc(a.tactic),
                    badge(a.confidence),
                    esc(a.basis)
                ]))
            )
        )}

        ${investigationSection("Event Timeline",
            table(
                ["Original Timestamp", "Timestamp Quality", "Event"],
                arr(c.events).map(e => row([
                    esc(e.ts_original),
                    esc(e.ts_quality),
                    esc(e.summary)
                ]))
            )
        )}

        ${investigationSection("SOAR Playbooks",
            table(
                ["Playbook", "Tier", "Review", "Proposed Actions"],
                arr(c.tickets).map(t => row([
                    esc(t.playbook_id),
                    esc(t.tier),
                    badge(t.review_status),
                    esc(arr(t.proposed_actions).join(", "))
                ]))
            )
        )}

        ${investigationSection("Response Decisions",
            table(
                ["Phase", "Tier", "Action", "Decision", "Analyst"],
                decisions.map(r => row([
                    esc(r.phase),
                    esc(r.tier),
                    esc(r.action),
                    badge(r.decision),
                    esc(r.decided_by)
                ]))
            )
        )}

        ${investigationSection("Forensic Evidence",
            arr(c.evidence_files).map(e => `
                <div class="evidence-card">
                    <small>Evidence Path</small>
                    <div>${esc(e.path)}</div>
                    <small>Recorded SHA-256</small>
                    <code>${esc(e.sha256)}</code>
                </div>
            `).join("") ||
            `<p class="muted">No evidence files recorded.</p>`
        )}

        <details class="investigation-section">
            <summary>View Original Raw JSON</summary>
            <pre>${esc(pretty(c))}</pre>
        </details>

        <p class="muted">
            Evidence-based tabletop investigation.
            No real response actions are executed.
        </p>
    `;

    if (!$("detail-dialog").open) {
        $("detail-dialog").showModal();
    }
}
