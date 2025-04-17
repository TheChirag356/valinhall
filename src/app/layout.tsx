import type { Metadata } from "next";
import { Fira_Code, Belanosima } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";

const firaCode = Fira_Code({
  variable: "--font-fira-code",
  subsets: ["latin"],
});

const belanosima = Belanosima({
  subsets: ["latin"],
  variable: "--font-belanosima",
  weight: ["400", "700"],
});


export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
          <body
            className={`${firaCode.variable} ${belanosima.variable} antialiased bg-[#181818]`}
          >
            <ThemeProvider
              attribute="class"
              defaultTheme="system"
              enableSystem
              disableTransitionOnChange
            >
              {children}
            </ThemeProvider>
          </body>
        </html>
  )
}