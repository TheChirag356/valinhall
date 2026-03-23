<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
</script>

<section
	class="dot-matrix relative flex min-h-[921px] flex-col justify-center overflow-hidden border-b border-border/20 px-6 md:px-12"
>
	<!-- Ghosted background text -->
	<div class="pointer-events-none absolute top-0 right-0 p-12 opacity-10 select-none">
		<span class="font-headline text-[20rem] leading-none font-black tracking-tighter">VALIN</span>
	</div>

	<div class="relative z-10 max-w-6xl">
		<p class="mb-4 font-headline text-sm tracking-[0.3em] text-primary uppercase">
			AI-Assisted Automated Security Testing Tool
		</p>
		<h1
			class="mb-8 font-headline text-6xl leading-[0.85] font-bold tracking-tighter text-foreground md:text-9xl"
		>
			VALINHALL
		</h1>
		<div class="flex flex-col items-start gap-6 md:flex-row md:items-center">
			<Button
				variant="default"
				class="shimmer h-auto rounded-xs px-10 py-6 font-headline text-lg font-bold tracking-widest text-primary-foreground uppercase hover:opacity-80"
			>
				Run a Scan
			</Button>
			<div class="flex flex-col border-l border-border/30 pl-6">
				<span class="font-headline text-xs tracking-widest text-muted-foreground uppercase"
					>System Status</span
				>
				<span class="font-headline text-lg text-foreground uppercase">All Nodes Operational</span>
			</div>
		</div>
	</div>

	<!-- Scroll indicator -->
	<div class="absolute bottom-10 left-6 flex items-center gap-4 md:left-12">
		<span class="font-headline text-[10px] tracking-[0.5em] text-muted-foreground uppercase"
			>Initiate Dive</span
		>
		<div class="h-px w-12 bg-border"></div>
	</div>
</section>
