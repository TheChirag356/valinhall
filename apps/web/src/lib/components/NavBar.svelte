<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
	import { dev } from '$app/environment';
</script>

<nav
	class="sticky top-0 z-50 flex w-full items-center justify-between border-b border-border/10 bg-background px-6 py-4"
>
	<div class="font-headline text-2xl font-bold tracking-tighter text-primary uppercase">
		Valinhall
	</div>
	<!-- <div class="hidden md:flex gap-8 items-center font-headline uppercase tracking-tighter">
		<a class="text-muted-foreground hover:text-foreground transition-colors duration-200" href="#">Scan</a>
		<a class="text-muted-foreground hover:text-foreground transition-colors duration-200" href="#">Audit</a>
		<a class="text-muted-foreground hover:text-foreground transition-colors duration-200" href="#">Reports</a>
	</div> -->
	<a href={dev ? 'http://localhost:5173' : 'https://dash.valinhall.chiragarora.me'} target="_blank">
		<Button
			variant="default"
			class="rounded-xs bg-primary px-6 py-2 font-headline text-sm font-bold tracking-tighter text-primary-foreground uppercase hover:bg-primary/90"
		>
			Console
		</Button>
	</a>
</nav>
