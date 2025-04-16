import Hero from "@/app/home/Hero"
import Navbar from "@/app/home/Navbar"
import HowItWorks from "@/app/home/HowItWorks"
import FAQ from "@/app/home/FrequentlyAskedQuestions"
import WhatWeCanDo from "@/app/home/WhatWeCanDo"
import Footer from "@/app/home/Footer"

export default function Home() {
  return (
    <main className="min-h-dvh relative overflow-hidden font-[family-name:var(--font-fira-code)] bg-[#e8e8e8] dark:bg-[#181818]">
      <div>
        <Navbar />
        <Hero />
        <HowItWorks />
        <WhatWeCanDo />
        <FAQ />
        <Footer />
      </div>
    </main>
  )
}