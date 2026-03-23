<script lang="ts">
	import { page } from '$app/stores';

	const links = [
		{ href: '/', label: 'Dashboard', icon: '🛡️' },
		{ href: '/scan', label: 'New Scan', icon: '🔍' },
		{ href: '/report', label: 'Reports', icon: '📊' },
		{ href: '/audit', label: 'Dep Audit', icon: '📦' },
		{ href: '/history', label: 'History', icon: '🕑' },
	];
</script>

<aside
	class="flex h-full w-60 flex-col border-r border-white/5 bg-[#09091380] backdrop-blur-xl"
>
	<!-- Logo -->
	<div class="flex items-center gap-3 border-b border-white/5 px-5 py-5">
		<div
			class="flex h-9 w-9 items-center justify-center rounded-xl bg-linear-to-br from-indigo-500 to-violet-600 text-lg shadow-lg"
		>
			🛡️
		</div>
		<div>
			<div
				class="bg-linear-to-r from-indigo-400 to-violet-400 bg-clip-text text-base font-black tracking-tight text-transparent"
			>
				Valinhall
			</div>
			<div class="text-[10px] font-medium text-slate-500">Security Platform</div>
		</div>
	</div>

	<!-- Nav -->
	<nav class="flex-1 space-y-1 px-3 py-4">
		<p class="section-title px-2">Navigation</p>
		{#each links as link}
			<a
				href={link.href}
				class="nav-link {$page.url.pathname === link.href ||
				($page.url.pathname.startsWith(link.href) && link.href !== '/')
					? 'active'
					: ''}"
			>
				<span class="text-base">{link.icon}</span>
				{link.label}
			</a>
		{/each}
	</nav>

	<!-- Footer -->
	<div class="border-t border-white/5 px-4 py-4">
		<div class="flex items-center gap-2">
			<div class="pulse-dot"></div>
			<span class="text-xs text-slate-500">Scanner Engine Ready</span>
		</div>
		<div class="mt-2 text-[10px] text-slate-600">
			v0.1.0 · OWASP 2026
		</div>
	</div>
</aside>
