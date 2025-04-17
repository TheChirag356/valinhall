import type { Metadata } from "next";
import { Fira_Code, Belanosima } from "next/font/google";
import "../globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import Footer from "@/app/(landingpage)/home/Footer";
import Navbar from "@/app/(landingpage)/home/Navbar";

const firaCode = Fira_Code({
  variable: "--font-fira-code",
  subsets: ["latin"],
});

const belanosima = Belanosima({
  subsets: ["latin"],
  variable: "--font-belanosima",
  weight: ["400", "700"],
});

export const metadata: Metadata = {
  title: {
    default: "Valinhall - AI Penetration Testing",
    template: "%s | Valinhall",
  },
  description: "Identify vulnerabilities in your web applications with AI."
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
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
          <Navbar />
          {children}
          <Footer />
        </ThemeProvider>
      </body>
    </html>
  );
}
