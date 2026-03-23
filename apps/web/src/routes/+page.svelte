<script lang="ts">
	import NavBar from '$lib/components/NavBar.svelte';
	import HeroSection from '$lib/components/HeroSection.svelte';
	import BentoGrid from '$lib/components/BentoGrid.svelte';
	import HowItWorks from '$lib/components/HowItWorks.svelte';
	import DashboardPreview from '$lib/components/DashboardPreview.svelte';
	import CtaSection from '$lib/components/CtaSection.svelte';
	import SiteFooter from '$lib/components/SiteFooter.svelte';
</script>

<div class="flex flex-col min-h-screen">
	<NavBar />

	<main class="grow">
		<HeroSection />
		<BentoGrid />
		<HowItWorks />
		<DashboardPreview />
		<CtaSection />
	</main>

	<SiteFooter />
</div>
