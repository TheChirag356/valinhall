<script lang="ts">
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';
	import NavSidebar from '$lib/components/NavSidebar.svelte';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<link rel="preconnect" href="https://fonts.googleapis.com" />
	<link
		rel="stylesheet"
		href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap"
	/>
	<title>Valinhall — Security Dashboard</title>
</svelte:head>

<div class="flex h-screen overflow-hidden">
	<NavSidebar />
	<main class="flex-1 overflow-y-auto">
		{@render children()}
	</main>
</div>
