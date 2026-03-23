<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
</script>

<section class="dot-matrix relative min-h-[921px] flex flex-col justify-center px-6 md:px-12 overflow-hidden border-b border-border/20">
	<!-- Ghosted background text -->
	<div class="absolute top-0 right-0 p-12 opacity-10 pointer-events-none select-none">
		<span class="text-[20rem] font-black font-headline tracking-tighter leading-none">VNUL</span>
	</div>

	<div class="relative z-10 max-w-6xl">
		<p class="font-headline text-primary text-sm tracking-[0.3em] mb-4">PROTOCOL: SENTINEL_LOGIC_V2</p>
		<h1 class="text-6xl md:text-9xl font-headline font-bold text-foreground tracking-tighter leading-[0.85] mb-8">
			VALINHALL:<br />THE SENTINEL <span class="text-primary">LOGIC</span>
		</h1>
		<div class="flex flex-col md:flex-row gap-6 items-start md:items-center">
			<Button
				variant="default"
				class="shimmer text-primary-foreground hover:opacity-80 px-10 py-6 h-auto font-headline font-bold text-lg uppercase tracking-widest rounded-xs"
			>
				Run a Scan
			</Button>
			<div class="flex flex-col border-l border-border/30 pl-6">
				<span class="text-xs font-headline text-muted-foreground tracking-widest uppercase">System Status</span>
				<span class="text-foreground font-headline text-lg uppercase">All Nodes Operational</span>
			</div>
		</div>
	</div>

	<!-- Scroll indicator -->
	<div class="absolute bottom-10 left-6 md:left-12 flex items-center gap-4">
		<span class="text-[10px] font-headline tracking-[0.5em] uppercase text-muted-foreground">Initiate Dive</span>
		<div class="w-12 h-px bg-border"></div>
	</div>
</section>
