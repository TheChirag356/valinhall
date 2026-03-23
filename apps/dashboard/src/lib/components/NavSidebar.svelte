<script lang="ts">
	import { page } from '$app/stores';

	const links = [
		{ href: '/', label: 'Scan Status', icon: 'radar' },
		{ href: '/vulnerabilities', label: 'Vulnerabilities', icon: 'gpp_maybe' },
		{ href: '/environments', label: 'Environments', icon: 'layers' }
	];
</script>

<aside class="hidden md:flex flex-col h-screen w-64 bg-surface-container-low py-8 flex-shrink-0 z-50">
	<div class="px-6 mb-12">
		<div class="flex items-center gap-3">
			<div class="w-10 h-10 bg-primary-fixed flex items-center justify-center rounded-sm">
				<span class="material-symbols-outlined text-on-primary-fixed" style="font-variation-settings: 'FILL' 1;">shield</span>
			</div>
			<div>
				<h1 class="text-xl font-black text-white font-headline leading-none tracking-tight">VALINHALL</h1>
				<p class="font-headline text-[10px] font-medium uppercase text-gray-500 tracking-widest mt-1">Security Dashboard</p>
			</div>
		</div>
	</div>

	<nav class="flex-grow">
		<ul class="space-y-1">
			{#each links as link}
				<li class="group">
					<a
						class="px-6 py-4 flex items-center gap-4 transition-all duration-200 
						{$page.url.pathname === link.href ? 'bg-surface-container-high text-primary-fixed border-l-4 border-primary-fixed' : 'text-gray-500 hover:bg-surface-container-high hover:text-white'}"
						href={link.href}
					>
						<span class="material-symbols-outlined" style="{$page.url.pathname === link.href ? `font-variation-settings: 'FILL' 1;` : ''}">{link.icon}</span>
						<span class="font-headline text-xs font-medium uppercase tracking-widest">{link.label}</span>
					</a>
				</li>
			{/each}
		</ul>
	</nav>

	<div class="px-6 mt-auto">
		<a href="/scan" class="flex items-center justify-center w-full bg-primary-fixed text-on-primary-fixed font-headline font-bold py-4 rounded-sm hover:opacity-90 active:scale-95 transition-all uppercase text-xs tracking-widest cursor-pointer">
			NEW SCAN
		</a>
		<div class="mt-8 pt-8 border-t border-white/5 flex items-center gap-3">
			<div class="w-8 h-8 rounded-full bg-surface-container-highest overflow-hidden">
				<img alt="Valinhall Shield" class="w-full h-full object-cover" src="https://lh3.googleusercontent.com/aida-public/AB6AXuDRx4j3wl4BgWhF9wGGotmjGAWG-t9oeZzNN1koR8czZwzUX_ndsz1TAZChV9yMiZMJs1uJfb5nWF5OaOEAgYEsGC8NcnuzKiyaI6qkkqWtd7dC0R1dE1w8NMFpxAS76pLOE-2cBDQqtwN_O4V3BAYOuGqbdSBHpPkYZcvr8QNXvJzDS-a0zFc0VUrJEey_bvlr38WbcPrpiffBnCHXOvymynoQKg_qNOta8o04v_REcnDKSfaWr5BI3Q8APeqbscGoDF6D0QV8HQ" />
			</div>
			<div>
				<p class="text-[10px] font-headline font-bold uppercase text-white leading-none">Admin_v02</p>
				<p class="text-[10px] text-gray-500 font-headline uppercase">Operational</p>
			</div>
		</div>
	</div>
</aside>
