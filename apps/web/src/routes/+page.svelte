<div class="flex flex-col min-h-screen">

  <!-- ═══ TopNavBar ═══ -->
  <nav class="sticky top-0 z-50 flex justify-between items-center w-full px-6 py-4 bg-[#131313] border-b border-[#444933]/10">
    <div class="text-2xl font-bold text-[#C3F400] tracking-tighter font-headline uppercase">Valinhall</div>
    <div class="hidden md:flex gap-8 items-center font-headline uppercase tracking-tighter">
      <a class="text-gray-400 hover:text-white transition-colors duration-200" href="#">Scan</a>
      <a class="text-gray-400 hover:text-white transition-colors duration-200" href="#">Audit</a>
      <a class="text-gray-400 hover:text-white transition-colors duration-200" href="#">Reports</a>
    </div>
    <button
      id="nav-console"
      class="bg-[#C3F400] text-[#161E00] px-6 py-2 text-sm font-bold font-headline uppercase tracking-tighter active:scale-95 duration-100 cursor-pointer"
    >
      Console
    </button>
  </nav>

  <main class="flex-grow">

    <!-- ═══ Hero Section ═══ -->
    <section class="dot-matrix relative min-h-[921px] flex flex-col justify-center px-6 md:px-12 overflow-hidden border-b border-[#444933]/20">
      <!-- Ghosted background text -->
      <div class="absolute top-0 right-0 p-12 opacity-10 pointer-events-none select-none">
        <span class="text-[20rem] font-black font-headline tracking-tighter leading-none">VNUL</span>
      </div>

      <div class="relative z-10 max-w-6xl">
        <p class="font-headline text-[#C3F400] text-sm tracking-[0.3em] mb-4">PROTOCOL: SENTINEL_LOGIC_V2</p>
        <h1 class="text-6xl md:text-9xl font-headline font-bold text-white tracking-tighter leading-[0.85] mb-8">
          VALINHALL:<br />THE SENTINEL <span class="text-[#C3F400]">LOGIC</span>
        </h1>
        <div class="flex flex-col md:flex-row gap-6 items-start md:items-center">
          <button
            id="hero-run-scan"
            class="shimmer text-[#161E00] px-10 py-4 font-headline font-bold text-lg uppercase tracking-widest active:opacity-80 transition-all rounded-xs cursor-pointer"
          >
            Run a Scan
          </button>
          <div class="flex flex-col border-l border-[#444933]/30 pl-6">
            <span class="text-xs font-headline text-[#8E9379] tracking-widest uppercase">System Status</span>
            <span class="text-white font-headline text-lg uppercase">All Nodes Operational</span>
          </div>
        </div>
      </div>

      <!-- Scroll indicator -->
      <div class="absolute bottom-10 left-6 md:left-12 flex items-center gap-4">
        <span class="text-[10px] font-headline tracking-[0.5em] uppercase text-[#8E9379]">Initiate Dive</span>
        <div class="w-12 h-px bg-[#444933]"></div>
      </div>
    </section>

    <!-- ═══ Feature Section (Bento Grid) ═══ -->
    <section class="py-24 px-6 md:px-12 bg-[#131313]">
      <div class="grid grid-cols-1 md:grid-cols-12 gap-4 max-w-7xl mx-auto">

        <!-- AI-Assisted Red-teaming -->
        <div class="md:col-span-8 bg-[#1C1B1B] p-8 border-l-4 border-[#C3F400] relative overflow-hidden h-[400px]">
          <div class="relative z-10 h-full flex flex-col justify-between">
            <span class="text-xs font-headline text-[#C3F400] tracking-widest uppercase">Automated Intelligence</span>
            <h3 class="text-4xl md:text-6xl font-headline font-bold text-white tracking-tighter leading-none max-w-md">
              AI-ASSISTED RED-TEAMING
            </h3>
            <p class="text-[#C4C9AC] max-w-sm font-body text-sm leading-relaxed">
              Simulate high-fidelity adversarial attacks using neural-driven payload generation. Autonomous discovery of zero-day vectors.
            </p>
          </div>
          <!-- decorative overlay -->
          <div class="absolute inset-0 bg-gradient-to-r from-transparent to-[#C3F400]/5 pointer-events-none"></div>
          <div class="absolute top-0 right-0 h-full w-1/2 opacity-10 mix-blend-overlay pointer-events-none"
            style="background: linear-gradient(135deg, #1a2a0a 0%, #0a1a1a 100%);">
          </div>
        </div>

        <!-- OWASP Card -->
        <div class="md:col-span-4 bg-[#2A2A2A] p-8 flex flex-col justify-between h-[400px]">
          <div class="flex justify-between items-start">
            <span class="material-symbols-outlined text-[#C3F400] scale-150">gpp_maybe</span>
            <div class="flex flex-col items-end gap-1">
              <div class="w-1.5 h-1.5 bg-[#C3F400]"></div>
              <div class="w-1.5 h-1.5 bg-[#C3F400]/50"></div>
              <div class="w-1.5 h-1.5 bg-[#C3F400]/20"></div>
            </div>
          </div>
          <div>
            <h3 class="text-2xl font-headline font-bold text-white uppercase tracking-tight mb-4">OWASP 2026 READY</h3>
            <p class="text-xs font-body text-[#C4C9AC] leading-relaxed">
              Future-proofed heuristics mapping against next-gen vulnerability frameworks.
            </p>
          </div>
        </div>

        <!-- Rust-Core CLI -->
        <div class="md:col-span-4 bg-[#0E0E0E] border border-[#444933]/10 p-8 h-[400px] flex flex-col justify-end">
          <div class="mb-auto">
            <span class="text-[10px] font-headline text-[#8E9379] tracking-widest uppercase">CLI Interface</span>
          </div>
          <h3 class="text-3xl font-headline font-bold text-white mb-4">RUST-CORE<br />BINARY</h3>
          <p class="text-xs font-body text-[#C4C9AC]">
            Blazing fast, memory-safe analysis engine compiled directly for bare-metal performance.
          </p>
          <div class="mt-6 font-mono text-[10px] text-[#C3F400] bg-black/40 p-2 border-l border-[#C3F400]">
            $ valinhall scan --help
          </div>
        </div>

        <!-- Stats -->
        <div class="md:col-span-8 bg-[#1C1B1B] p-8 relative h-[400px] flex items-center">
          <div class="grid grid-cols-2 gap-12 w-full">
            <div>
              <h3 class="text-5xl font-headline font-bold text-white tracking-tighter mb-4">99.9%</h3>
              <p class="text-xs font-headline text-[#8E9379] uppercase tracking-widest">Accuracy Rate</p>
            </div>
            <div>
              <h3 class="text-5xl font-headline font-bold text-white tracking-tighter mb-4">&lt;15ms</h3>
              <p class="text-xs font-headline text-[#8E9379] uppercase tracking-widest">Latency Floor</p>
            </div>
          </div>
          <div class="absolute inset-0 opacity-5 pointer-events-none dot-matrix"></div>
        </div>

      </div>
    </section>

    <!-- ═══ How It Works ═══ -->
    <section class="py-24 px-6 md:px-12 bg-[#0E0E0E] border-y border-[#444933]/10">
      <div class="max-w-4xl mx-auto">
        <h2 class="text-4xl font-headline font-bold text-center mb-24 tracking-tighter text-white uppercase">
          THE SURGICAL PROCESS
        </h2>
        <div class="space-y-32">

          <!-- Step 01 -->
          <div class="flex flex-col md:flex-row gap-12 items-center">
            <div class="w-full md:w-1/2 flex justify-center">
              <div class="w-24 h-24 rounded-full border border-[#C3F400] flex items-center justify-center text-[#C3F400] font-headline text-4xl">
                01
              </div>
            </div>
            <div class="w-full md:w-1/2 text-left">
              <h4 class="text-2xl font-headline font-bold text-white mb-4 uppercase tracking-tight">INGRESS &amp; MAPPING</h4>
              <p class="text-[#C4C9AC] font-body">
                Input your domain or CIDR. Valinhall's sentinel nodes map the entire attack surface in sub-seconds.
              </p>
            </div>
          </div>

          <!-- Step 02 -->
          <div class="flex flex-col md:flex-row-reverse gap-12 items-center">
            <div class="w-full md:w-1/2 flex justify-center">
              <div class="w-24 h-24 rounded-full border border-[#8E9379] flex items-center justify-center text-[#8E9379] font-headline text-4xl">
                02
              </div>
            </div>
            <div class="w-full md:w-1/2 text-right">
              <h4 class="text-2xl font-headline font-bold text-white mb-4 uppercase tracking-tight">HEURISTIC ANALYSIS</h4>
              <p class="text-[#C4C9AC] font-body">
                Our proprietary Rust engine performs deep-packet inspection and behavioral logic checks against 40k+ patterns.
              </p>
            </div>
          </div>

          <!-- Step 03 -->
          <div class="flex flex-col md:flex-row gap-12 items-center">
            <div class="w-full md:w-1/2 flex justify-center">
              <div class="w-24 h-24 rounded-full border border-[#C3F400] flex items-center justify-center text-[#C3F400] font-headline text-4xl">
                03
              </div>
            </div>
            <div class="w-full md:w-1/2 text-left">
              <h4 class="text-2xl font-headline font-bold text-white mb-4 uppercase tracking-tight">AUTONOMOUS REPORTING</h4>
              <p class="text-[#C4C9AC] font-body">
                Zero-noise documentation delivered via CLI, Webhook, or Dashboard. Actionable remediation steps only.
              </p>
            </div>
          </div>

        </div>
      </div>
    </section>

    <!-- ═══ Dashboard Preview ═══ -->
    <section class="py-32 px-6 md:px-12 bg-[#131313] overflow-hidden">
      <div class="max-w-7xl mx-auto">
        <div class="bg-[#1C1B1B] rounded-xs border border-[#444933]/20 overflow-hidden shadow-2xl">

          <!-- Window chrome -->
          <div class="flex items-center gap-2 px-6 py-4 bg-[#2A2A2A] border-b border-[#444933]/10">
            <div class="w-2 h-2 rounded-full bg-[#FFB4AB]/40"></div>
            <div class="w-2 h-2 rounded-full bg-[#C3F400]/40"></div>
            <div class="w-2 h-2 rounded-full bg-[#444933]"></div>
            <div class="ml-4 text-[10px] font-headline text-[#8E9379] tracking-widest uppercase">
              VALINHALL_CORE // DASHBOARD_VIEW
            </div>
          </div>

          <div class="flex flex-col md:flex-row min-h-[600px]">

            <!-- Sidebar mock -->
            <div class="w-full md:w-64 bg-[#1C1B1B] py-8 flex flex-col">
              <div class="px-6 mb-8">
                <div class="text-xl font-black text-white font-headline">VALINHALL</div>
                <div class="text-[10px] font-medium text-[#C3F400] uppercase font-headline">Security Dashboard</div>
              </div>
              <nav class="flex flex-col font-headline text-xs font-medium uppercase">
                <div class="bg-[#2A2A2A] text-[#C3F400] border-l-4 border-[#C3F400] px-6 py-3 flex items-center gap-3">
                  <span class="material-symbols-outlined text-sm">radar</span>
                  Scan Status
                </div>
                <div class="text-gray-500 px-6 py-3 flex items-center gap-3 hover:bg-[#2A2A2A] hover:text-white cursor-pointer transition-all">
                  <span class="material-symbols-outlined text-sm">gpp_maybe</span>
                  Vulnerabilities
                </div>
                <div class="text-gray-500 px-6 py-3 flex items-center gap-3 hover:bg-[#2A2A2A] hover:text-white cursor-pointer transition-all">
                  <span class="material-symbols-outlined text-sm">layers</span>
                  Environments
                </div>
              </nav>
            </div>

            <!-- Main content mock -->
            <div class="flex-grow p-8 bg-[#0E0E0E]">
              <div class="flex justify-between items-end mb-12">
                <div>
                  <h2 class="text-3xl font-headline font-bold text-white tracking-tighter">ENVIRONMENT_THREAT_MAP</h2>
                  <p class="text-xs font-body text-[#8E9379]">Real-time telemetry from active scanning nodes.</p>
                </div>
                <div class="text-right">
                  <span class="text-xs font-headline text-[#C3F400] uppercase tracking-widest">Live Updates</span>
                  <div class="flex items-center gap-2 text-2xl font-headline text-white">
                    <div class="w-2 h-2 rounded-full bg-[#C3F400] animate-pulse"></div>
                    2.4 GB/s
                  </div>
                </div>
              </div>

              <!-- Stat cards -->
              <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div class="p-6 bg-[#2A2A2A]/50 border border-[#444933]/10">
                  <span class="text-[10px] font-headline text-[#8E9379] uppercase tracking-widest">Active Scans</span>
                  <div class="text-4xl font-headline font-bold text-white mt-2">04</div>
                </div>
                <div class="p-6 bg-[#2A2A2A]/50 border border-[#444933]/10">
                  <span class="text-[10px] font-headline text-[#8E9379] uppercase tracking-widest">Critical Risks</span>
                  <div class="text-4xl font-headline font-bold text-[#FFB4AB] mt-2">12</div>
                </div>
                <div class="p-6 bg-[#2A2A2A]/50 border border-[#444933]/10">
                  <span class="text-[10px] font-headline text-[#8E9379] uppercase tracking-widest">Remediation Rate</span>
                  <div class="text-4xl font-headline font-bold text-[#C3F400] mt-2">88%</div>
                </div>
              </div>

              <!-- Network mesh visualization -->
              <div class="h-64 bg-[#1C1B1B] border border-[#444933]/10 relative overflow-hidden flex items-center justify-center dot-matrix">
                <!-- Animated grid lines -->
                <svg class="absolute inset-0 w-full h-full opacity-20" xmlns="http://www.w3.org/2000/svg">
                  <defs>
                    <pattern id="mesh" width="60" height="60" patternUnits="userSpaceOnUse">
                      <path d="M 60 0 L 0 0 0 60" fill="none" stroke="#C3F400" stroke-width="0.5"/>
                    </pattern>
                  </defs>
                  <rect width="100%" height="100%" fill="url(#mesh)" />
                  <line x1="0" y1="50%" x2="100%" y2="50%" stroke="#C3F400" stroke-width="1" opacity="0.4"/>
                  <line x1="50%" y1="0" x2="50%" y2="100%" stroke="#C3F400" stroke-width="1" opacity="0.4"/>
                  <circle cx="50%" cy="50%" r="40" fill="none" stroke="#C3F400" stroke-width="1" opacity="0.5"/>
                  <circle cx="50%" cy="50%" r="80" fill="none" stroke="#C3F400" stroke-width="0.5" opacity="0.3"/>
                </svg>
                <div class="relative z-10 text-center">
                  <p class="font-headline text-xs text-[#C3F400] tracking-[0.4em] uppercase">Visualizing Network Mesh...</p>
                </div>
              </div>
            </div>

          </div>
        </div>
      </div>
    </section>

    <!-- ═══ CTA Final ═══ -->
    <section class="py-32 px-6 text-center border-t border-[#444933]/20 bg-[#0E0E0E]">
      <h2 class="text-5xl md:text-7xl font-headline font-bold text-white tracking-tighter mb-8 uppercase">
        SECURE THE PERIMETER
      </h2>
      <p class="max-w-xl mx-auto text-[#C4C9AC] mb-12 font-body">
        Valinhall is the final word in proactive security. Deploy the sentinel logic today.
      </p>
      <div class="flex flex-col md:flex-row justify-center gap-4">
        <button
          id="cta-free-scan"
          class="bg-[#C3F400] text-[#161E00] px-12 py-4 font-headline font-bold uppercase tracking-widest active:scale-95 transition-all cursor-pointer"
        >
          Start Free Scan
        </button>
        <button
          id="cta-contact"
          class="border border-[#8E9379] text-white px-12 py-4 font-headline font-bold uppercase tracking-widest hover:bg-white hover:text-black transition-all cursor-pointer"
        >
          Contact Ops
        </button>
      </div>
    </section>

  </main>

  <!-- ═══ Footer ═══ -->
  <footer class="flex justify-between items-center w-full px-6 py-3 border-t border-white/5 bg-[#131313]">
    <div class="text-[#C3F400] font-headline text-[10px] tracking-widest uppercase">VALINHALL LOGIC V2.4.0</div>
    <div class="flex gap-8 font-headline text-[10px] tracking-widest uppercase">
      <a class="text-gray-600 hover:text-[#C3F400] transition-colors" href="#">Documentation</a>
      <a class="text-gray-600 hover:text-[#C3F400] transition-colors" href="#">System Status</a>
      <a class="text-gray-600 hover:text-[#C3F400] transition-colors" href="#">CLI Release</a>
    </div>
    <div class="text-gray-600 font-headline text-[10px] tracking-widest uppercase">© 2026  Valinhall</div>
  </footer>

</div>
