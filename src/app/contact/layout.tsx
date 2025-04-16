import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Contact",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return <div>{children}</div>;
}
