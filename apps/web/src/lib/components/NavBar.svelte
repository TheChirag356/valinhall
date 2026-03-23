<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
</script>

<nav class="sticky top-0 z-50 flex justify-between items-center w-full px-6 py-4 bg-background border-b border-border/10">
	<div class="text-2xl font-bold text-primary tracking-tighter font-headline uppercase">Valinhall</div>
	<div class="hidden md:flex gap-8 items-center font-headline uppercase tracking-tighter">
		<a class="text-muted-foreground hover:text-foreground transition-colors duration-200" href="#">Scan</a>
		<a class="text-muted-foreground hover:text-foreground transition-colors duration-200" href="#">Audit</a>
		<a class="text-muted-foreground hover:text-foreground transition-colors duration-200" href="#">Reports</a>
	</div>
	<Button
		variant="default"
		class="bg-primary text-primary-foreground hover:bg-primary/90 rounded-xs px-6 py-2 text-sm font-bold font-headline uppercase tracking-tighter"
	>
		Console
	</Button>
</nav>
