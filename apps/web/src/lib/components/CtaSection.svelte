<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
</script>

<section class="py-32 px-6 text-center border-t border-border/20 bg-[#0E0E0E]">
	<h2 class="text-5xl md:text-7xl font-headline font-bold text-foreground tracking-tighter mb-8 uppercase">
		SECURE YOUR APPLICATIONS
	</h2>
	<p class="max-w-xl mx-auto text-muted-foreground mb-12 font-body">
		Valinhall is the first and the last tool for your multitool belt.
	</p>
	<div class="flex flex-col md:flex-row justify-center gap-4">
		<Button
			id="cta-free-scan"
			variant="default"
			class="bg-primary text-primary-foreground hover:bg-primary/90 px-12 py-6 h-auto font-headline font-bold uppercase tracking-widest rounded-xs"
		>
			Start Free Scan
		</Button>
		<Button
			id="cta-contact"
			variant="outline"
			class="border border-muted-foreground text-foreground px-12 py-6 h-auto font-headline font-bold uppercase tracking-widest hover:bg-foreground hover:text-background rounded-xs"
		>
			Contact Ops
		</Button>
	</div>
</section>
