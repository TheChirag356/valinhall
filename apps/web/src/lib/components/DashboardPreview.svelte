<section class="py-32 px-6 md:px-12 bg-background overflow-hidden">
	<div class="max-w-7xl mx-auto">
		<div class="bg-card rounded-xs border border-border/20 overflow-hidden shadow-2xl">

			<!-- Window chrome -->
			<div class="flex items-center gap-2 px-6 py-4 bg-accent border-b border-border/10">
				<div class="w-2 h-2 rounded-full bg-destructive/40"></div>
				<div class="w-2 h-2 rounded-full bg-primary/40"></div>
				<div class="w-2 h-2 rounded-full bg-border"></div>
				<div class="ml-4 text-[10px] font-headline text-muted-foreground tracking-widest uppercase">
					VALINHALL_CORE // DASHBOARD_VIEW
				</div>
			</div>

			<div class="flex flex-col md:flex-row min-h-[600px]">

				<!-- Sidebar mock -->
				<div class="w-full md:w-64 bg-card py-8 flex flex-col">
					<div class="px-6 mb-8">
						<div class="text-xl font-black text-foreground font-headline">VALINHALL</div>
						<div class="text-[10px] font-medium text-primary uppercase font-headline">Security Dashboard</div>
					</div>
					<nav class="flex flex-col font-headline text-xs font-medium uppercase">
						<div class="bg-accent text-primary border-l-4 border-primary px-6 py-3 flex items-center gap-3">
							<span class="material-symbols-outlined text-sm">radar</span>
							Scan Status
						</div>
						<div class="text-muted-foreground px-6 py-3 flex items-center gap-3 hover:bg-accent hover:text-foreground cursor-pointer transition-all">
							<span class="material-symbols-outlined text-sm">gpp_maybe</span>
							Vulnerabilities
						</div>
						<div class="text-muted-foreground px-6 py-3 flex items-center gap-3 hover:bg-accent hover:text-foreground cursor-pointer transition-all">
							<span class="material-symbols-outlined text-sm">layers</span>
							Environments
						</div>
					</nav>
				</div>

				<!-- Main content mock -->
				<div class="grow p-8 bg-[#0E0E0E]">
					<div class="flex justify-between items-end mb-12">
						<div>
							<h2 class="text-3xl font-headline font-bold text-foreground tracking-tighter">ENVIRONMENT_THREAT_MAP</h2>
							<p class="text-xs font-body text-muted-foreground">Real-time telemetry from active scanning nodes.</p>
						</div>
						<div class="text-right">
							<span class="text-xs font-headline text-primary uppercase tracking-widest">Live Updates</span>
							<div class="flex items-center gap-2 text-2xl font-headline text-foreground">
								<div class="w-2 h-2 rounded-full bg-primary animate-pulse"></div>
								2.4 GB/s
							</div>
						</div>
					</div>

					<!-- Stat cards -->
					<div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
						<div class="p-6 bg-accent/50 border border-border/10">
							<span class="text-[10px] font-headline text-muted-foreground uppercase tracking-widest">Active Scans</span>
							<div class="text-4xl font-headline font-bold text-foreground mt-2">04</div>
						</div>
						<div class="p-6 bg-accent/50 border border-border/10">
							<span class="text-[10px] font-headline text-muted-foreground uppercase tracking-widest">Critical Risks</span>
							<div class="text-4xl font-headline font-bold text-destructive mt-2">12</div>
						</div>
						<div class="p-6 bg-accent/50 border border-border/10">
							<span class="text-[10px] font-headline text-muted-foreground uppercase tracking-widest">Remediation Rate</span>
							<div class="text-4xl font-headline font-bold text-primary mt-2">88%</div>
						</div>
					</div>

					<!-- Network mesh visualization -->
					<div class="h-64 bg-card border border-border/10 relative overflow-hidden flex items-center justify-center dot-matrix">
						<!-- Animated grid lines -->
						<svg class="absolute inset-0 w-full h-full opacity-20" xmlns="http://www.w3.org/2000/svg">
							<defs>
								<pattern id="mesh" width="60" height="60" patternUnits="userSpaceOnUse">
									<path d="M 60 0 L 0 0 0 60" fill="none" stroke="var(--color-primary)" stroke-width="0.5"/>
								</pattern>
							</defs>
							<rect width="100%" height="100%" fill="url(#mesh)" />
							<line x1="0" y1="50%" x2="100%" y2="50%" stroke="var(--color-primary)" stroke-width="1" opacity="0.4"/>
							<line x1="50%" y1="0" x2="50%" y2="100%" stroke="var(--color-primary)" stroke-width="1" opacity="0.4"/>
							<circle cx="50%" cy="50%" r="40" fill="none" stroke="var(--color-primary)" stroke-width="1" opacity="0.5"/>
							<circle cx="50%" cy="50%" r="80" fill="none" stroke="var(--color-primary)" stroke-width="0.5" opacity="0.3"/>
						</svg>
						<div class="relative z-10 text-center">
							<p class="font-headline text-xs text-primary tracking-[0.4em] uppercase">Visualizing Network Mesh...</p>
						</div>
					</div>
				</div>

			</div>
		</div>
	</div>
</section>
