<script lang="ts">
	import { countBySeverity, generateDemoResult, type ScanResult } from '$lib/types';

	let result = $state<ScanResult>(generateDemoResult());
	let counts = $derived(countBySeverity(result.findings));
	let total = $derived(result.findings.length);
</script>

<svelte:head>
	<title>Valinhall — Scan Status</title>
</svelte:head>

<!-- Hero Section: Active Scan -->
<section class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
	<div class="lg:col-span-8 bg-surface-container-low relative overflow-hidden p-8 border-l-4 border-primary-fixed min-h-[300px] flex flex-col justify-between">
		<div class="absolute top-0 right-0 w-32 h-32 dot-matrix opacity-20"></div>
		
		<div>
			<div class="flex items-center gap-2 mb-2">
				<span class="text-primary-fixed font-headline text-[10px] uppercase font-bold tracking-[0.2em]">Active_Monitor</span>
				<span class="h-px grow bg-outline-variant/30"></span>
			</div>
			<h2 class="text-5xl font-headline font-black text-white tracking-tighter uppercase mb-2">Active Scans</h2>
			<p class="text-on-surface-variant/60 font-body text-sm max-w-md">System wide packet inspection and vulnerability mapping in real-time execution.</p>
		</div>
		
		<div class="mt-8 space-y-6">
			<!-- Scan Entry 1 -->
			<div class="bg-surface-container-high p-6 group">
				<div class="flex flex-col md:flex-row md:items-end justify-between gap-4 mb-4">
					<div class="space-y-1">
						<div class="flex items-center gap-3">
							<span class="text-[10px] bg-primary-fixed text-on-primary-fixed px-1 font-headline font-bold">{result.id.slice(0, 7).toUpperCase()}</span>
							<h3 class="font-headline font-bold text-lg text-white truncate">{result.target}</h3>
						</div>
						<p class="text-[11px] font-mono text-on-surface-variant uppercase tracking-tight">PATH: 192.168.1.1/api/v2/authentication</p>
					</div>
					<div class="text-right">
						<p class="text-primary-fixed font-headline font-black text-2xl tracking-tighter leading-none">84%</p>
						<p class="text-[10px] text-gray-500 font-headline uppercase mt-1">Estimating: 2m 14s</p>
					</div>
				</div>
				<div class="w-full h-1.5 bg-background overflow-hidden flex">
					<div class="h-full bg-primary-fixed shadow-[0_0_10px_rgba(195,244,0,0.5)]" style="width: 84%;"></div>
				</div>
			</div>
		</div>
	</div>

	<!-- Summary Stats: Bento Grid Pattern -->
	<div class="lg:col-span-4 grid grid-cols-2 gap-4 h-full">
		<div class="bg-surface-container-low p-6 flex flex-col justify-between border-t-2 border-error text-white">
			<span class="text-[10px] font-headline font-bold text-error uppercase tracking-widest">Critical</span>
			<span class="text-7xl font-headline font-black leading-none my-4">{counts.critical}</span>
			<div class="w-full h-1 bg-error/20"></div>
		</div>
		
		<div class="bg-surface-container-low p-6 flex flex-col justify-between border-t-2 border-primary-fixed text-white">
			<span class="text-[10px] font-headline font-bold text-primary-fixed uppercase tracking-widest">High</span>
			<span class="text-7xl font-headline font-black leading-none my-4">{counts.high}</span>
			<div class="w-full h-1 bg-primary-fixed/20"></div>
		</div>
		
		<div class="bg-surface-container-low p-6 flex flex-col justify-between border-t-2 border-on-surface-variant text-white">
			<span class="text-[10px] font-headline font-bold text-on-surface-variant uppercase tracking-widest">Medium</span>
			<span class="text-7xl font-headline font-black leading-none my-4">{counts.medium}</span>
			<div class="w-full h-1 bg-on-surface-variant/20"></div>
		</div>
		
		<div class="bg-surface-container-low p-6 flex flex-col justify-between border-t-2 border-secondary-container text-white">
			<span class="text-[10px] font-headline font-bold text-secondary-container uppercase tracking-widest">Low</span>
			<span class="text-7xl font-headline font-black leading-none my-4">{counts.low}</span>
			<div class="w-full h-1 bg-secondary-container/20"></div>
		</div>
	</div>
</section>

<!-- Recent History -->
<section>
	<div class="flex items-center justify-between mb-6">
		<h2 class="text-xl font-headline font-bold text-white uppercase tracking-tighter">Recent Scan History</h2>
		<div class="h-px flex-grow mx-6 bg-outline-variant/20"></div>
		<button class="text-[10px] font-headline font-bold text-primary-fixed uppercase tracking-[0.2em] flex items-center gap-2 hover:opacity-70 cursor-pointer">
			View All Logs <span class="material-symbols-outlined text-xs">arrow_forward</span>
		</button>
	</div>
	
	<div class="space-y-3">
		<!-- Table-like Header -->
		<div class="hidden md:grid grid-cols-6 px-6 text-[10px] font-headline font-bold text-gray-500 uppercase tracking-widest pb-2">
			<div class="col-span-2">Object Name</div>
			<div>ID / Signature</div>
			<div>Start Time</div>
			<div>Risk Profile</div>
			<div class="text-right">Action</div>
		</div>
		
		<!-- Scan Item 1 -->
		<div class="bg-surface-container-low hover:bg-surface-container-high transition-colors p-5 md:p-6 md:grid md:grid-cols-6 items-center gap-4 group">
			<div class="col-span-2 flex items-center gap-4 mb-4 md:mb-0">
				<div class="w-10 h-10 flex-shrink-0 bg-surface-container-highest flex items-center justify-center">
					<span class="material-symbols-outlined text-on-surface-variant">dns</span>
				</div>
				<div>
					<p class="font-headline font-bold text-white text-sm">STAGING_DATA_SYNC</p>
					<p class="text-[10px] text-gray-500 font-mono uppercase">staging-01.valinhall.io</p>
				</div>
			</div>
			
			<div class="mb-4 md:mb-0">
				<span class="text-[10px] font-mono text-on-surface-variant font-bold">SHA-256: 0x98A...1F</span>
			</div>
			
			<div class="mb-4 md:mb-0">
				<p class="text-[11px] text-on-surface uppercase leading-tight">14 Oct 2023</p>
				<p class="text-[10px] text-gray-500 uppercase leading-tight">14:22:10 UTC</p>
			</div>
			
			<div class="mb-4 md:mb-0">
				<span class="inline-flex items-center px-2 py-0.5 bg-error/10 text-error text-[10px] font-headline font-bold rounded-none tracking-widest">THREAT_DETECTED</span>
			</div>
			
			<div class="text-right">
				<button class="text-[10px] font-headline font-bold text-white hover:text-primary-fixed border-b border-white/10 pb-1 uppercase transition-all cursor-pointer">Download PDF</button>
			</div>
		</div>
		
		<!-- Scan Item 2 -->
		<div class="bg-surface-container-low hover:bg-surface-container-high transition-colors p-5 md:p-6 md:grid md:grid-cols-6 items-center gap-4 group">
			<div class="col-span-2 flex items-center gap-4 mb-4 md:mb-0">
				<div class="w-10 h-10 flex-shrink-0 bg-surface-container-highest flex items-center justify-center">
					<span class="material-symbols-outlined text-on-surface-variant">cloud</span>
				</div>
				<div>
					<p class="font-headline font-bold text-white text-sm">AWS_LAMBDA_RUNTIME</p>
					<p class="text-[10px] text-gray-500 font-mono uppercase">us-east-1/lambda/auth</p>
				</div>
			</div>
			
			<div class="mb-4 md:mb-0">
				<span class="text-[10px] font-mono text-on-surface-variant font-bold">SHA-256: 0xCC1...4E</span>
			</div>
			
			<div class="mb-4 md:mb-0">
				<p class="text-[11px] text-on-surface uppercase leading-tight">14 Oct 2023</p>
				<p class="text-[10px] text-gray-500 uppercase leading-tight">10:05:44 UTC</p>
			</div>
			
			<div class="mb-4 md:mb-0">
				<span class="inline-flex items-center px-2 py-0.5 bg-primary-fixed/10 text-primary-fixed text-[10px] font-headline font-bold rounded-none tracking-widest">SECURE_VERIFIED</span>
			</div>
			
			<div class="text-right">
				<button class="text-[10px] font-headline font-bold text-white hover:text-primary-fixed border-b border-white/10 pb-1 uppercase transition-all cursor-pointer">Download PDF</button>
			</div>
		</div>

		<!-- Scan Item 3 -->
		<div class="bg-surface-container-low hover:bg-surface-container-high transition-colors p-5 md:p-6 md:grid md:grid-cols-6 items-center gap-4 group">
			<div class="col-span-2 flex items-center gap-4 mb-4 md:mb-0">
				<div class="w-10 h-10 flex-shrink-0 bg-surface-container-highest flex items-center justify-center">
					<span class="material-symbols-outlined text-on-surface-variant">settings_ethernet</span>
				</div>
				<div>
					<p class="font-headline font-bold text-white text-sm">EDGE_ROUTER_AUDIT</p>
					<p class="text-[10px] text-gray-500 font-mono uppercase">edge-lon-04.internal</p>
				</div>
			</div>
			
			<div class="mb-4 md:mb-0">
				<span class="text-[10px] font-mono text-on-surface-variant font-bold">SHA-256: 0xBB5...09</span>
			</div>
			
			<div class="mb-4 md:mb-0">
				<p class="text-[11px] text-on-surface uppercase leading-tight">13 Oct 2023</p>
				<p class="text-[10px] text-gray-500 uppercase leading-tight">22:15:00 UTC</p>
			</div>
			
			<div class="mb-4 md:mb-0">
				<span class="inline-flex items-center px-2 py-0.5 bg-secondary/10 text-secondary text-[10px] font-headline font-bold rounded-none tracking-widest">MINIMAL_FINDINGS</span>
			</div>
			
			<div class="text-right">
				<button class="text-[10px] font-headline font-bold text-white hover:text-primary-fixed border-b border-white/10 pb-1 uppercase transition-all cursor-pointer">Download PDF</button>
			</div>
		</div>
	</div>
</section>

<!-- Data Visual Overlay -->
<section class="grid grid-cols-1 md:grid-cols-2 gap-8 mt-12">
	<div class="p-8 bg-surface-container-low relative border-l border-white/5">
		<div class="flex items-center justify-between mb-8">
			<h3 class="text-sm font-headline font-black text-white uppercase tracking-widest">Threat Vector Map</h3>
			<span class="text-[10px] text-primary-fixed font-headline uppercase">Live_Stream</span>
		</div>
		
		<div class="aspect-video bg-surface-container-highest relative flex items-center justify-center overflow-hidden">
			<div class="absolute inset-0 dot-matrix opacity-10"></div>
			<img alt="Cybersecurity world map visualization" class="w-full h-full object-cover grayscale opacity-40 mix-blend-overlay" src="https://lh3.googleusercontent.com/aida-public/AB6AXuD-ZdlEXILYJVqMiJtk8s2oh-9dD2fbd75nijrn3oCxi6GFjEynnITZRjZvVQHUfpWdRgOyd9p6Vkm4R4xMjWFxhvvPIEKtuv-EXKWU4ETRUGmr86QehDJY3uusKBtISgqLRgj60zj_1O_t1pYQFQCkDZ73eXpbRr7Z09Qy_VuXAvDbFfQigxwQfk9htHADZFO-XBGicgHdH3pGKCOEaEgDwdFq6es3Py3xwRDeJOewW-hoaiTP1CRVNsBS13AAbFiTCShg-D6r3w"/>
			
			<div class="absolute inset-0 flex items-center justify-center">
				<div class="w-32 h-32 border-2 border-primary-fixed/20 rounded-full flex items-center justify-center animate-pulse">
					<div class="w-16 h-16 border border-primary-fixed/40 rounded-full flex items-center justify-center">
						<div class="w-2 h-2 bg-primary-fixed rounded-full"></div>
					</div>
				</div>
			</div>
			
			<div class="absolute bottom-4 left-4 text-[10px] font-mono text-primary-fixed">
				LAT: 51.5074 N<br/>
				LON: 0.1278 W
			</div>
		</div>
	</div>

	<div class="p-8 bg-surface-container-low flex flex-col justify-between border-l border-white/5">
		<div>
			<h3 class="text-sm font-headline font-black text-white uppercase tracking-widest mb-2">Operational Integrity</h3>
			<p class="text-xs text-on-surface-variant font-body mb-6">Aggregate security health index across all active environments.</p>
			
			<div class="space-y-4">
				<div>
					<div class="flex justify-between text-[10px] font-headline uppercase font-bold mb-1 text-white">
						<span>System Health</span>
						<span>99.98%</span>
					</div>
					<div class="h-1 bg-surface-container-highest w-full">
						<div class="h-full bg-primary-fixed-dim" style="width: 99%;"></div>
					</div>
				</div>
				
				<div>
					<div class="flex justify-between text-[10px] font-headline uppercase font-bold mb-1 text-white">
						<span>Encrypted Density</span>
						<span>82%</span>
					</div>
					<div class="h-1 bg-surface-container-highest w-full">
						<div class="h-full bg-primary-fixed-dim" style="width: 82%;"></div>
					</div>
				</div>
				
				<div>
					<div class="flex justify-between text-[10px] font-headline uppercase font-bold mb-1 text-white">
						<span>Latency Response</span>
						<span>4ms</span>
					</div>
					<div class="h-1 bg-surface-container-highest w-full">
						<div class="h-full bg-primary-fixed-dim" style="width: 15%;"></div>
					</div>
				</div>
			</div>
		</div>
		
		<div class="mt-8 flex gap-2">
			<div class="bg-surface-variant/40 px-3 py-1 text-[9px] font-headline font-bold text-white uppercase">STABLE</div>
			<div class="bg-surface-variant/40 px-3 py-1 text-[9px] font-headline font-bold text-white uppercase">ENCRYPTED</div>
		</div>
	</div>
</section>
