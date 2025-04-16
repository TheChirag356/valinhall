import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Select Project",
  description: "Select your project",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>{children}</body>
    </html>
  );
}
