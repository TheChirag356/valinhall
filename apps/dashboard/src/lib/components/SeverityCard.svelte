<script lang="ts">
	interface Props {
		label: string;
		count: number;
		severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
		total?: number;
	}

	let { label, count, severity, total }: Props = $props();

	const configs = {
		critical: { bg: 'rgba(220,38,38,0.1)', border: 'rgba(220,38,38,0.2)', text: '#fca5a5', glow: 'rgba(220,38,38,0.15)' },
		high:     { bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.2)', text: '#fdba74', glow: 'rgba(249,115,22,0.15)' },
		medium:   { bg: 'rgba(250,204,21,0.1)', border: 'rgba(250,204,21,0.2)', text: '#fde047', glow: 'rgba(250,204,21,0.15)' },
		low:      { bg: 'rgba(96,165,250,0.1)', border: 'rgba(96,165,250,0.2)',  text: '#93c5fd', glow: 'rgba(96,165,250,0.15)' },
		info:     { bg: 'rgba(107,114,128,0.1)', border: 'rgba(107,114,128,0.2)', text: '#9ca3af', glow: 'rgba(107,114,128,0.12)' },
	};

	// Use $derived so it reacts to prop changes
	let c = $derived(configs[severity]);
	let pct = $derived(total && total > 0 ? Math.round((count / total) * 100) : 0);
</script>

<div
	class="relative overflow-hidden rounded-xl p-4 text-center transition-all"
	style="background: {c.bg}; border: 1px solid {c.border}; box-shadow: 0 0 20px {c.glow}"
>
	<div class="text-4xl font-black" style="color: {c.text}">{count}</div>
	<div class="mt-1 text-[11px] font-bold uppercase tracking-widest text-slate-500">{label}</div>
	{#if total !== undefined}
		<div class="mt-3 h-1 w-full overflow-hidden rounded-full bg-white/5">
			<div
				class="h-full rounded-full transition-all duration-700"
				style="width: {pct}%; background: {c.text}"
			></div>
		</div>
		<div class="mt-1 text-[10px] text-slate-600">{pct}% of total</div>
	{/if}
</div>
