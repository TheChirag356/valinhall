<script lang="ts">
	import type { SupplyFinding } from '$lib/types';

	let ecosystem = $state('all');
	let path = $state('./');
	let loading = $state(false);
	let results = $state<SupplyFinding[]>([]);
	let hasRun = $state(false);

	// Demo findings
	const demoFindings: SupplyFinding[] = [
		{ package: 'lodash', version: '4.17.20', ecosystem: 'npm', severity: 'high',
		  title: 'Prototype Pollution', cve: 'CVE-2021-23337', fix_version: '4.17.21', osv_id: 'GHSA-35jh-r3h4-6jhm' },
		{ package: 'axios', version: '0.21.1', ecosystem: 'npm', severity: 'high',
		  title: 'Server-Side Request Forgery', cve: 'CVE-2021-3749', fix_version: '0.21.2', osv_id: 'GHSA-xvch-5gv4-984h' },
		{ package: 'json5', version: '1.0.1', ecosystem: 'npm', severity: 'high',
		  title: 'Prototype Pollution', cve: 'CVE-2022-46175', fix_version: '1.0.2', osv_id: 'GHSA-9c47-m6qq-7p4h' },
		{ package: 'openssl', version: '1.1.1t', ecosystem: 'rust', severity: 'critical',
		  title: 'OpenSSL X.509 Policy Processing Information Disclosure', cve: 'CVE-2023-0465', fix_version: '1.1.1u', osv_id: 'RUSTSEC-2023-0007' },
		{ package: 'golang.org/x/net', version: 'v0.7.0', ecosystem: 'Go', severity: 'high',
		  title: 'HTML injection via Go templates', cve: 'CVE-2023-29400', fix_version: 'v0.9.0', osv_id: 'GO-2023-1751' },
		{ package: 'semver', version: '7.3.7', ecosystem: 'npm', severity: 'medium',
		  title: 'Regular Expression Denial of Service', cve: 'CVE-2022-25883', fix_version: '7.5.2', osv_id: 'GHSA-c2qf-rxjj-qqgw' },
		{ package: 'word-wrap', version: '1.2.3', ecosystem: 'npm', severity: 'medium',
		  title: 'Regular Expression Denial of Service', cve: 'CVE-2023-26115', fix_version: '1.2.4', osv_id: 'GHSA-j8xg-fqg3-53r7' },
	];

	function runDemo() {
		loading = true;
		hasRun = false;
		setTimeout(() => {
			results = demoFindings;
			hasRun = true;
			loading = false;
		}, 1200);
	}

	let filtered = $derived(
		ecosystem === 'all' ? results : results.filter((r) => r.ecosystem.toLowerCase() === ecosystem)
	);

	const severityColors: Record<string, string> = {
		critical: '#dc2626', high: '#f97316', medium: '#facc15', low: '#60a5fa',
	};

	let stats = $derived({
		critical: results.filter((r) => r.severity === 'critical').length,
		high: results.filter((r) => r.severity === 'high').length,
		medium: results.filter((r) => r.severity === 'medium').length,
		low: results.filter((r) => r.severity === 'low').length,
	});
</script>

<svelte:head>
	<title>Valinhall — Dependency Audit</title>
</svelte:head>

<div class="p-8">
	<div class="mb-6">
		<h1 class="text-2xl font-bold text-slate-100">Dependency Audit</h1>
		<p class="mt-1 text-sm text-slate-500">
			Scan Node.js, Rust, and Go dependency lock files against the OSV.dev vulnerability database.
		</p>
	</div>

	<!-- Config -->
	<div class="glass mb-6 p-5">
		<div class="grid grid-cols-3 gap-4">
			<div>
				<label class="label" for="audit-path">Project Root Path</label>
				<input id="audit-path" bind:value={path} class="input font-mono" placeholder="./" />
			</div>
			<div>
				<label class="label" for="eco-select">Ecosystems</label>
				<select id="eco-select" bind:value={ecosystem} class="input">
					<option value="all">All (Node + Rust + Go)</option>
					<option value="npm">Node.js (npm)</option>
					<option value="rust">Rust (crates.io)</option>
					<option value="go">Go</option>
				</select>
			</div>
			<div class="flex items-end">
				<button onclick={runDemo} disabled={loading} class="btn btn-primary w-full">
					{#if loading}
						<div class="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent"></div>
						Scanning…
					{:else}
						📦 Run Audit
					{/if}
				</button>
			</div>
		</div>
		<p class="mt-3 text-[11px] text-slate-600">
			<strong class="text-slate-500">CLI equivalent:</strong>
			<code class="font-mono text-indigo-400">valinhall audit --path "{path}" --ecosystems "{ecosystem === 'all' ? 'node,rust,go' : ecosystem}"</code>
		</p>
	</div>

	<!-- Results -->
	{#if loading}
		<div class="glass flex items-center justify-center gap-3 py-16">
			<div class="h-8 w-8 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent"></div>
			<span class="text-slate-400">Querying OSV.dev database…</span>
		</div>
	{:else if hasRun}
		<!-- Stats Row -->
		<div class="mb-5 grid grid-cols-4 gap-4">
			{#each [['Critical', 'critical'], ['High', 'high'], ['Medium', 'medium'], ['Low', 'low']] as [label, sev]}
				<div class="glass rounded-xl p-4 text-center" style="border-left: 3px solid {severityColors[sev] ?? '#6b7280'}">
					<div class="text-2xl font-black" style="color: {severityColors[sev]}">{stats[sev as keyof typeof stats]}</div>
					<div class="mt-0.5 text-[11px] font-semibold uppercase tracking-widest text-slate-500">{label}</div>
				</div>
			{/each}
		</div>

		<!-- Ecosystem filter -->
		<div class="mb-4 flex gap-2">
			{#each ['all', 'npm', 'rust', 'go'] as eco}
				<button
					onclick={() => (ecosystem = eco)}
					class="badge cursor-pointer {ecosystem === eco ? 'bg-indigo-500/30 text-indigo-300' : 'bg-white/5 text-slate-400 hover:bg-white/10'}"
				>{eco}</button>
			{/each}
		</div>

		{#if filtered.length === 0}
			<div class="glass py-16 text-center">
				<p class="text-2xl mb-2">✅</p>
				<p class="text-slate-400">No vulnerabilities found for this ecosystem.</p>
			</div>
		{:else}
			<div class="space-y-2">
				{#each filtered as vuln}
					<div class="glass p-4 flex items-start justify-between gap-4" style="border-left: 3px solid {severityColors[vuln.severity] ?? '#6b7280'}">
						<div class="min-w-0">
							<div class="mb-1 flex flex-wrap items-center gap-2">
								<span class="badge badge-{vuln.severity}">{vuln.severity}</span>
								<span class="badge bg-white/5 text-slate-400 font-mono">{vuln.ecosystem}</span>
								{#if vuln.cve}
									<span class="badge bg-indigo-500/15 text-indigo-400">{vuln.cve}</span>
								{/if}
							</div>
							<p class="font-semibold text-slate-100">{vuln.title}</p>
							<p class="mt-0.5 font-mono text-sm text-slate-400">
								{vuln.package} <span class="text-slate-600">@</span>{vuln.version}
							</p>
						</div>
						<div class="shrink-0 text-right">
							{#if vuln.fix_version}
								<p class="text-[11px] text-slate-500">Fix available</p>
								<p class="font-mono text-sm text-green-400">→ {vuln.fix_version}</p>
							{:else}
								<p class="text-[11px] text-slate-600">No fix yet</p>
							{/if}
							<p class="mt-1 font-mono text-[10px] text-slate-600">{vuln.osv_id}</p>
						</div>
					</div>
				{/each}
			</div>
		{/if}
	{:else}
		<div class="glass flex flex-col items-center py-20 text-center">
			<div class="mb-4 text-5xl">📦</div>
			<p class="text-slate-400">Configure options above and run the audit to check your dependencies.</p>
		</div>
	{/if}
</div>
