import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box: a site dir, a stubbed clamscan/freshclam/which/apt-get, a signature dir. Built BEFORE importing.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "scan-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const mode = path.join(base, "mode"), calls = path.join(base, "calls");
const stub = (n, body) => { fs.writeFileSync(path.join(bin, n), `#!/bin/bash\necho "${n} $*" >> "${calls}"\n${body}\n`); fs.chmodSync(path.join(bin, n), 0o755); };
stub("which", `[ -f "${base}/installed" ] && exit 0 || exit 1`);
stub("apt-get", `touch "${base}/installed"; exit 0`);
stub("freshclam", `mkdir -p "${base}/db"; touch "${base}/db/main.cvd"; exit 0`);
stub("clamscan", `[ "$1" = "--version" ] && { echo "ClamAV 1.4.2/27500/Tue Oct 20 08:00:00 2026"; exit 0; }
case "$(cat "${mode}")" in
  clean) printf 'Known viruses: 8700000\\nEngine version: 1.4.2\\nScanned directories: 120\\nScanned files: 4321\\nInfected files: 0\\nData scanned: 300.00 MB\\nTime: 42.000 sec (0 m 42 s)\\n'; exit 0;;
  infected) d="\${@: -1}"; printf '%s\\n' "$d/wp-content/uploads/2026/10/shell.php: Php.Malware.Agent-1234567 FOUND" "$d/wp-content/plugins/evil/x.php: Php.Backdoor.Generic-7 FOUND"; printf 'Known viruses: 8700000\\nScanned files: 4321\\nInfected files: 2\\nTime: 40.000 sec (0 m 40 s)\\n'; exit 1;;
  error) echo "LibClamAV Error: cli_loaddb(): No supported database files found" >&2; exit 2;;
esac`);
const www = path.join(base, "www"); fs.mkdirSync(path.join(www, "site.com/htdocs"), { recursive: true });
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_WWW_DIR: www, SCAN_REPORT_DIR: path.join(base, "reports"), CLAMAV_DB_DIR: path.join(base, "db") });

const { parseClamscan, formatReport, reportFor } = await import(path.join(A, "src/operations/scan.js"));
const { operations } = await import(path.join(A, "src/operations/index.js"));
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };
const callLog = () => fs.readFileSync(calls, "utf8");

// 1) parsing + the report, pure
const parsed = parseClamscan("/x/a.php: Php.Malware.Agent-1 FOUND\nKnown viruses: 10\nScanned files: 3\nInfected files: 1\n");
assert.deepEqual(parsed, { infected: [{ file: "/x/a.php", signature: "Php.Malware.Agent-1" }], summary: { "Known viruses": "10", "Scanned files": "3", "Infected files": "1" } });
const rep = formatReport({ domain: "site.com", server: "SEO_1", dir: "/x", startedAt: new Date(0), finishedAt: new Date(5000), version: "ClamAV 1.4.2", ...parsed, exitCode: 1, errors: [], rawTail: "" });
assert.match(rep, /Result    : INFECTED — 1 file\(s\)/); assert.match(rep, /\/x\/a\.php\n    Php\.Malware\.Agent-1/); assert.match(rep, /Scanned files       : 3/);
console.log("1. clamscan output parsed; report lists result, infected files and summary");

// 2) first scan installs ClamAV + downloads signatures; a clean site = completed job + report
fs.writeFileSync(mode, "clean");
await operations.scan.run({ id: "job-aaaa-1111" }, helpers, { domain: "site.com" });
assert.match(callLog(), /apt-get install -y -qq clamav/); assert.match(callLog(), /freshclam --quiet/);
assert.match(callLog(), /clamscan --recursive --infected .*--exclude-dir=\/\\\.git\/ .*site\.com\/htdocs/);
const r1 = await reportFor("job-aaaa-1111");
assert.ok(r1 && r1.name === "job-aaaa-1111_site.com.txt");
assert.match(fs.readFileSync(r1.path, "utf8"), /Result    : CLEAN[\s\S]*Scanned files       : 4321/);
console.log("2. ClamAV installed on first use, signatures fetched, clean scan -> report written");

// 3) second scan: nothing re-installed, fresh signatures not re-downloaded
fs.writeFileSync(calls, "");
await operations.scan.run({ id: "job-bbbb-2222" }, helpers, { domain: "site.com" });
assert.ok(!/apt-get/.test(callLog()) && !/freshclam/.test(callLog()), "no install, no freshclam within a day");
console.log("3. already installed + fresh signatures -> straight to the scan");

// 4) infected: the job FAILS (so it stands out), each hit is in the log, the report has the list
fs.writeFileSync(mode, "infected"); lines.length = 0;
await assert.rejects(() => operations.scan.run({ id: "job-cccc-3333" }, helpers, { domain: "site.com" }), /2 infected file\(s\) found on site\.com/);
assert.match(lines.join("\n"), /FOUND Php\.Malware\.Agent-1234567  \/wp-content\/uploads\/2026\/10\/shell\.php/);
const r3 = await reportFor("job-cccc-3333");
assert.match(fs.readFileSync(r3.path, "utf8"), /Result    : INFECTED — 2 file\(s\)[\s\S]*plugins\/evil\/x\.php\n    Php\.Backdoor\.Generic-7/);
console.log("4. infected -> job fails, hits in the log, full list in the report");

// 5) clamscan error (exit 2, nothing found) -> failed with the reason; unknown site refused; bad ids get no report
fs.writeFileSync(mode, "error");
await assert.rejects(() => operations.scan.run({ id: "job-dddd-4444" }, helpers, { domain: "site.com" }), /clamscan reported an error \(exit 2\): LibClamAV Error/);
await assert.rejects(() => operations.scan.run({ id: "job-eeee-5555" }, helpers, { domain: "ghost.com" }), /not on this server/);
assert.equal(await reportFor("../../etc/passwd"), null); assert.equal(await reportFor("job-zzzz-0000"), null);
assert.equal(operations.scan.validate({ domain: "https://Site.com/" }).clean.domain, "site.com");
console.log("5. clamscan error reported; unknown site refused; report lookup is id-only");

console.log("\nPASS: ClamAV scans run, report findings, and leave a downloadable report");
fs.rmSync(base, { recursive: true, force: true });
