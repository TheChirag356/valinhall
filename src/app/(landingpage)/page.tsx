import Hero from "@/app/(landingpage)/home/Hero"
import HowItWorks from "@/app/(landingpage)/home/HowItWorks"
import FAQ from "@/app/(landingpage)/home/FrequentlyAskedQuestions"
import Message from "@/app/(landingpage)/home/Message";
import WhatWeCanDo from "@/app/(landingpage)/home/WhatWeCanDo"

export default function Home() {
  return (
    <main className="min-h-dvh relative overflow-hidden font-[family-name:var(--font-fira-code)] bg-[#e8e8e8] dark:bg-[#181818]">
      <div>
        <Hero />
        <HowItWorks />
        <WhatWeCanDo />
        <FAQ />
        <Message />
      </div>
    </main>
  )
}