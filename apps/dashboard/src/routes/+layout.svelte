<script lang="ts">
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';
	import NavSidebar from '$lib/components/NavSidebar.svelte';
	import TopNavBar from '$lib/components/TopNavBar.svelte';
	import Footer from '$lib/components/Footer.svelte';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<link rel="preconnect" href="https://fonts.googleapis.com" />
	<link
		href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700;800;900&family=Inter:wght@300;400;500;600;700&display=swap"
		rel="stylesheet"
	/>
	<link
		href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"
		rel="stylesheet"
	/>
	<title>Valinhall — Security Dashboard</title>
</svelte:head>

<!-- Global Layout Wrapper -->
<div class="flex min-h-screen overflow-hidden bg-background text-on-background font-body selection:bg-primary-fixed selection:text-on-primary-fixed dark">
	<NavSidebar />
	<main class="flex-grow flex flex-col h-screen overflow-y-auto bg-background relative">
		<TopNavBar />
		<div class="p-8 space-y-8 flex-grow">
			{@render children()}
		</div>
		<Footer />
	</main>
</div>
