<script lang="ts">
	import type { Finding } from '$lib/types';

	interface Props {
		finding: Finding;
	}

	let { finding }: Props = $props();
	let open = $state(false);

	const severityBorder: Record<string, string> = {
		critical: '#dc2626',
		high: '#f97316',
		medium: '#facc15',
		low: '#60a5fa',
		info: '#6b7280',
	};

	const owaspCodes: Record<string, string> = {
		BrokenAccessControl: 'A01',
		CryptographicFailures: 'A02',
		SupplyChainFailures: 'A03',
		InsecureDesign: 'A04',
		SecurityMisconfiguration: 'A05',
		VulnerableComponents: 'A06',
		AuthFailures: 'A07',
		IntegrityFailures: 'A08',
		LoggingFailures: 'A09',
		ExceptionalConditions: 'A10',
		LlmVulnerability: 'LLM',
	};
</script>

<div
	class="finding-bar glass overflow-hidden"
	style="border-left-color: {severityBorder[finding.severity] ?? '#6b7280'}"
>
	<!-- Summary Row -->
	<button
		onclick={() => (open = !open)}
		class="flex w-full cursor-pointer items-start gap-4 px-5 py-4 text-left transition-colors hover:bg-white/3"
	>
		<div class="mt-0.5 shrink-0 transition-transform {open ? 'rotate-90' : ''}">
			<svg class="h-3.5 w-3.5 text-slate-500" viewBox="0 0 24 24" fill="currentColor">
				<path d="M8.59 16.59L13.17 12 8.59 7.41 10 6l6 6-6 6z" />
			</svg>
		</div>

		<div class="min-w-0 flex-1">
			<div class="mb-2 flex flex-wrap items-center gap-2">
				<span class="badge badge-{finding.severity}">{finding.severity}</span>
				<span class="badge bg-white/5 text-slate-400"
					>{owaspCodes[finding.category] ?? finding.category}</span
				>
				<span class="badge bg-white/5 text-slate-500">{finding.source}</span>
			</div>
			<h3 class="text-sm font-semibold leading-snug text-slate-100">{finding.title}</h3>
			{#if finding.endpoint}
				<p class="mt-1 truncate font-mono text-[11px] text-slate-500">{finding.endpoint}</p>
			{/if}
		</div>
	</button>

	<!-- Expanded Details -->
	{#if open}
		<div class="space-y-4 border-t border-white/5 px-5 pb-5 pt-4">
			<div>
				<p class="section-title">Description</p>
				<p class="text-sm leading-relaxed text-slate-300">{finding.description}</p>
			</div>

			{#if finding.evidence}
				<div>
					<p class="section-title">Evidence</p>
					<pre
						class="overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-black/40 p-3 font-mono text-[11px] text-green-400">{finding.evidence}</pre>
				</div>
			{/if}

			<div>
				<p class="section-title">Remediation</p>
				<p class="text-sm leading-relaxed text-slate-300">{finding.remediation}</p>
			</div>
		</div>
	{/if}
</div>
