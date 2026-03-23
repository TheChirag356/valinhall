<script lang="ts">
	import type { ScanHistoryEntry } from '$lib/types';

	const history: ScanHistoryEntry[] = [
		{ id: 'demo-scan-001', target: 'http://demo.testfire.net', timestamp: new Date().toISOString(),
		  critical: 2, high: 4, medium: 3, low: 2, total: 13 },
		{ id: 'scan-20260310', target: 'https://juiceshop.local:3000', timestamp: '2026-03-10T09:14:00Z',
		  critical: 5, high: 7, medium: 4, low: 1, total: 18 },
		{ id: 'scan-20260305', target: 'https://api.internal.corp', timestamp: '2026-03-05T16:32:00Z',
		  critical: 0, high: 2, medium: 6, low: 8, total: 17 },
		{ id: 'scan-20260228', target: './apps/backend', timestamp: '2026-02-28T11:00:00Z',
		  critical: 1, high: 3, medium: 2, low: 5, total: 11 },
	];

	function riskLevel(entry: ScanHistoryEntry) {
		if (entry.critical > 0) return { label: 'CRITICAL', color: '#dc2626' };
		if (entry.high > 0) return { label: 'HIGH', color: '#f97316' };
		if (entry.medium > 0) return { label: 'MEDIUM', color: '#facc15' };
		return { label: 'LOW', color: '#60a5fa' };
	}
</script>

<svelte:head>
	<title>Valinhall — Scan History</title>
</svelte:head>

<div class="p-8">
	<div class="mb-6 flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-slate-100">Scan History</h1>
			<p class="mt-1 text-sm text-slate-500">{history.length} past scans</p>
		</div>
		<a href="/scan" class="btn btn-primary">+ New Scan</a>
	</div>

	<div class="space-y-3">
		{#each history as entry}
			{@const risk = riskLevel(entry)}
			<div class="glass glass-hover p-5 flex items-center justify-between gap-4" style="border-left: 3px solid {risk.color}">
				<div class="min-w-0 flex-1">
					<div class="mb-1 flex items-center gap-3">
						<span class="badge font-mono text-[10px] bg-white/5 text-slate-400">{entry.id}</span>
						<span class="badge text-[10px] font-bold" style="background: {risk.color}22; color: {risk.color}; border: 1px solid {risk.color}44">{risk.label}</span>
					</div>
					<p class="font-mono text-sm font-medium text-blue-400 truncate">{entry.target}</p>
					<p class="mt-0.5 text-xs text-slate-500">{new Date(entry.timestamp).toLocaleString()}</p>
				</div>

				<!-- Mini severity bar -->
				<div class="flex items-center gap-3 shrink-0">
					{#each [{ label: 'C', count: entry.critical, color: '#dc2626' }, { label: 'H', count: entry.high, color: '#f97316' }, { label: 'M', count: entry.medium, color: '#facc15' }, { label: 'L', count: entry.low, color: '#60a5fa' }] as sev}
						<div class="text-center min-w-[32px]">
							<div class="text-lg font-black" style="color: {sev.color}">{sev.count}</div>
							<div class="text-[9px] text-slate-600 uppercase">{sev.label}</div>
						</div>
					{/each}
					<div class="ml-2 w-px h-10 bg-white/5"></div>
					<a href="/report" class="btn btn-ghost py-1.5 px-3 text-xs ml-1">View →</a>
				</div>
			</div>
		{:else}
			<div class="glass py-16 text-center">
				<p class="text-4xl mb-3">🕑</p>
				<p class="text-slate-400">No scan history yet. Run your first scan to see results here.</p>
			</div>
		{/each}
	</div>
</div>
