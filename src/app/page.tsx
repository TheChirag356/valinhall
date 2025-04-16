import Hero from "@/components/Hero"
import Navbar from "@/components/Navbar"

export default function Home() {
  return (
    <main className="min-h-dvh relative overflow-hidden font-[family-name:var(--font-fira-code)] bg-[#e8e8e8] dark:bg-[#181818]">
      <div>
        <Navbar />
        <Hero />
      </div>
    </main>
  )
}