<script lang="ts">
	let target = $state('');
	let includesSast = $state(true);
	let includesDast = $state(true);
	let includesLlm = $state(false);
	let includesAudit = $state(true);
	let concurrency = $state(20);
	let timeout = $state(10);
	let outputPath = $state('./');

	let generating = $state(false);
	let command = $derived(buildCommand());

	function buildCommand() {
		const parts = ['valinhall scan', `--target "${target || 'https://example.com'}"`, `--output "${outputPath}"`];
		if (!includesDast) parts.push('--sast-only');
		if (!includesSast) parts.push('--dast-only');
		if (includesLlm) parts.push('--llm');
		parts.push(`--concurrency ${concurrency}`);
		parts.push(`--timeout ${timeout}`);
		return parts.join(' \\\n  ');
	}

	function copyCommand() {
		navigator.clipboard.writeText(command.replace(/\\\n  /g, ' '));
	}

	const modules = [
		{ id: 'sast', label: 'Static Analysis (SAST)', desc: 'Scans source code for secrets, SQLi sinks, unsafe patterns.', icon: '🔬', bind: 'includesSast' },
		{ id: 'dast', label: 'Dynamic Attack (DAST)', desc: 'Fires HTTP probes: SQLi, XSS, RCE, auth attacks.', icon: '⚡', bind: 'includesDast' },
		{ id: 'llm',  label: 'LLM Red-Team',          desc: 'Prompt injection, PII exfil, system prompt extraction.', icon: '🤖', bind: 'includesLlm' },
		{ id: 'audit', label: 'Dep Audit',              desc: 'Checks Node/Rust/Go deps against OSV.dev CVE database.', icon: '📦', bind: 'includesAudit' },
	];
</script>

<svelte:head>
	<title>Valinhall — New Scan</title>
</svelte:head>

<div class="p-8">
	<div class="mb-8">
		<h1 class="text-2xl font-bold text-slate-100">Configure Scan</h1>
		<p class="mt-1 text-sm text-slate-500">
			Set up your scan parameters. The CLI command is generated in real-time below.
		</p>
	</div>

	<div class="grid grid-cols-3 gap-6">
		<!-- Left: Config Form -->
		<div class="col-span-2 space-y-6">
			<!-- Target -->
			<div class="glass p-5">
				<p class="section-title">Target</p>
				<label class="label" for="target-url">URL or Local Path</label>
				<input
					id="target-url"
					bind:value={target}
					class="input font-mono"
					placeholder="https://example.com  or  ./my-project"
					type="text"
				/>
				<p class="mt-2 text-[11px] text-slate-600">
					Use a URL for DAST/LLM probes. Use a local directory path for SAST source scanning.
				</p>
			</div>

			<!-- Modules -->
			<div class="glass p-5">
				<p class="section-title">Scan Modules</p>
				<div class="grid grid-cols-2 gap-3">
					{#each modules as mod}
						{@const checked = mod.id === 'sast' ? includesSast : mod.id === 'dast' ? includesDast : mod.id === 'llm' ? includesLlm : includesAudit}
						<label
							class="flex cursor-pointer items-start gap-3 rounded-xl border p-4 transition-all {checked ? 'border-indigo-500/40 bg-indigo-500/10' : 'border-white/5 bg-white/2 hover:bg-white/5'}"
						>
							<input
								type="checkbox"
								class="mt-0.5 rounded accent-indigo-500"
								checked={checked}
								onchange={() => {
									if (mod.id === 'sast') includesSast = !includesSast;
									else if (mod.id === 'dast') includesDast = !includesDast;
									else if (mod.id === 'llm') includesLlm = !includesLlm;
									else includesAudit = !includesAudit;
								}}
							/>
							<div>
								<div class="flex items-center gap-2">
									<span>{mod.icon}</span>
									<span class="text-sm font-semibold text-slate-200">{mod.label}</span>
								</div>
								<p class="mt-0.5 text-xs text-slate-500">{mod.desc}</p>
							</div>
						</label>
					{/each}
				</div>
			</div>

			<!-- Advanced -->
			<div class="glass p-5">
				<p class="section-title">Advanced Options</p>
				<div class="grid grid-cols-2 gap-4">
					<div>
						<label class="label" for="concurrency">Max Concurrent Requests</label>
						<input id="concurrency" bind:value={concurrency} type="number" min="1" max="100" class="input" />
					</div>
					<div>
						<label class="label" for="timeout">Request Timeout (seconds)</label>
						<input id="timeout" bind:value={timeout} type="number" min="1" max="120" class="input" />
					</div>
					<div class="col-span-2">
						<label class="label" for="output">Output Directory</label>
						<input id="output" bind:value={outputPath} type="text" class="input font-mono" placeholder="./" />
					</div>
				</div>
			</div>
		</div>

		<!-- Right: Generated Command -->
		<div class="space-y-4">
			<div class="glass p-5">
				<div class="mb-3 flex items-center justify-between">
					<p class="section-title mb-0">Generated Command</p>
					<button onclick={copyCommand} class="btn btn-ghost py-1.5 text-xs px-3">Copy</button>
				</div>
				<pre class="overflow-x-auto rounded-xl bg-black/50 p-4 font-mono text-xs leading-relaxed text-green-400 whitespace-pre-wrap">{command}</pre>
				<p class="mt-3 text-[11px] text-slate-600">Run this in your terminal after building the CLI with <code class="text-indigo-400">pnpm cli:build</code>.</p>
			</div>

			<!-- OWASP Coverage chips -->
			<div class="glass p-5">
				<p class="section-title">OWASP Coverage</p>
				<div class="flex flex-wrap gap-2">
					{#each ['A01','A02','A03','A04','A05','A06','A07','A08','A09','A10','LLM'] as code}
						<span class="badge bg-indigo-500/15 text-indigo-400 {code === 'LLM' && !includesLlm ? 'opacity-30' : ''}">{code}</span>
					{/each}
				</div>
				{#if !includesLlm}
					<p class="mt-2 text-[11px] text-slate-600">↑ Enable LLM module for A10/LLM coverage</p>
				{/if}
			</div>

			<!-- Quick Links -->
			<div class="glass p-5">
				<p class="section-title">Quick Actions</p>
				<div class="space-y-2">
					<a href="/" class="btn btn-ghost w-full justify-start text-sm">← Back to Dashboard</a>
					<a href="/report" class="btn btn-ghost w-full justify-start text-sm">📊 View Last Report</a>
					<a href="/audit" class="btn btn-ghost w-full justify-start text-sm">📦 Audit Dependencies</a>
				</div>
			</div>
		</div>
	</div>
</div>
