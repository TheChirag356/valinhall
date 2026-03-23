<script lang="ts">
	import SeverityCard from '$lib/components/SeverityCard.svelte';
	import FindingCard from '$lib/components/FindingCard.svelte';
	import { countBySeverity, countByCategory, generateDemoResult, OWASP_LABELS, SEVERITY_COLORS, type ScanResult, type Severity, type OwaspCategory } from '$lib/types';

	// Use demo data by default — replace with API call in production
	let result = $state<ScanResult>(generateDemoResult());
	let severityFilter = $state<Severity | 'all'>('all');

	let counts = $derived(countBySeverity(result.findings));
	let total = $derived(result.findings.length);

	let filtered = $derived(
		severityFilter === 'all'
			? result.findings
			: result.findings.filter((f) => f.severity === severityFilter)
	);

	let categoryBreakdown = $derived(
		Object.entries(countByCategory(result.findings))
			.sort(([, a], [, b]) => b - a)
			.slice(0, 8) as [OwaspCategory, number][]
	);

	// Top riskiest endpoint
	let topEndpoint = $derived(() => {
		const ep: Record<string, number> = {};
		for (const f of result.findings) if (f.endpoint) ep[f.endpoint] = (ep[f.endpoint] ?? 0) + 1;
		const sorted = Object.entries(ep).sort(([, a], [, b]) => b - a);
		return sorted[0]?.[0] ?? '—';
	});

	const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
</script>

<svelte:head>
	<title>Valinhall — Dashboard</title>
</svelte:head>

<div class="p-8">
	<!-- Header -->
	<div class="mb-8 flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-slate-100">Security Overview</h1>
			<p class="mt-0.5 text-sm text-slate-500">
				Last scan: <span class="font-mono text-slate-400">{result.target}</span> ·
				<span class="text-slate-500">{new Date(result.timestamp).toLocaleString()}</span>
			</p>
		</div>
		<a href="/scan" class="btn btn-primary">
			<svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
			</svg>
			New Scan
		</a>
	</div>

	<!-- Severity Summary Cards -->
	<div class="mb-6 grid grid-cols-5 gap-4">
		<SeverityCard label="Critical" count={counts.critical} severity="critical" total={total} />
		<SeverityCard label="High" count={counts.high} severity="high" total={total} />
		<SeverityCard label="Medium" count={counts.medium} severity="medium" total={total} />
		<SeverityCard label="Low" count={counts.low} severity="low" total={total} />
		<SeverityCard label="Info" count={counts.info} severity="info" total={total} />
	</div>

	<!-- Two-column stats row -->
	<div class="mb-6 grid grid-cols-2 gap-4">
		<!-- OWASP Category Breakdown -->
		<div class="glass p-5">
			<p class="section-title">OWASP Category Breakdown</p>
			<div class="space-y-3">
				{#each categoryBreakdown as [cat, count]}
					<div class="flex items-center gap-3">
						<span class="w-32 shrink-0 text-xs text-slate-400">{OWASP_LABELS[cat]?.slice(0, 22) ?? cat}</span>
						<div class="flex-1 overflow-hidden rounded-full bg-white/5" style="height:6px">
							<div
								class="h-full rounded-full bg-indigo-500 transition-all"
								style="width: {total > 0 ? (count / total) * 100 : 0}%"
							></div>
						</div>
						<span class="w-6 text-right text-xs font-bold text-slate-300">{count}</span>
					</div>
				{/each}
			</div>
		</div>

		<!-- Quick Stats -->
		<div class="glass p-5 flex flex-col gap-4">
			<p class="section-title">Scan Metadata</p>
			<div class="space-y-3 text-sm">
				<div class="flex justify-between border-b border-white/5 pb-3">
					<span class="text-slate-500">Scan ID</span>
					<span class="font-mono text-xs text-slate-300 truncate max-w-36">{result.id}</span>
				</div>
				<div class="flex justify-between border-b border-white/5 pb-3">
					<span class="text-slate-500">Target</span>
					<span class="font-mono text-xs text-blue-400 truncate max-w-44">{result.target}</span>
				</div>
				<div class="flex justify-between border-b border-white/5 pb-3">
					<span class="text-slate-500">Total Findings</span>
					<span class="font-bold text-slate-200">{total}</span>
				</div>
				<div class="flex justify-between border-b border-white/5 pb-3">
					<span class="text-slate-500">Risk Score</span>
					<span class="font-bold {counts.critical > 0 ? 'text-red-400' : counts.high > 0 ? 'text-orange-400' : 'text-yellow-400'}">
						{counts.critical > 0 ? 'CRITICAL' : counts.high > 0 ? 'HIGH' : 'MEDIUM'}
					</span>
				</div>
				<div class="flex justify-between">
					<span class="text-slate-500">Top Endpoint</span>
					<span class="font-mono text-xs text-slate-400 truncate max-w-40">{topEndpoint()}</span>
				</div>
			</div>
			<a href="/report" class="btn btn-ghost mt-auto text-center justify-center">View Full Report →</a>
		</div>
	</div>

	<!-- Findings List -->
	<div class="glass p-5">
		<!-- Filter bar -->
		<div class="mb-4 flex items-center gap-2 flex-wrap">
			<p class="section-title mr-2 mb-0">Findings</p>
			<button
				onclick={() => (severityFilter = 'all')}
				class="badge {severityFilter === 'all' ? 'bg-indigo-500/30 text-indigo-300 border-indigo-500/40' : 'bg-white/5 text-slate-400 hover:bg-white/10'} cursor-pointer"
			>All ({total})</button>
			{#each severities as sev}
				<button
					onclick={() => (severityFilter = sev)}
					class="badge badge-{sev} cursor-pointer {severityFilter === sev ? 'ring-1 ring-white/30' : ''}"
				>{sev} ({counts[sev]})</button>
			{/each}
		</div>

		<div class="space-y-2">
			{#each filtered as finding (finding.id)}
				<FindingCard {finding} />
			{:else}
				<div class="py-12 text-center text-slate-500">No findings match this filter.</div>
			{/each}
		</div>
	</div>
</div>
