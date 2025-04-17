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

import type { Metadata } from "next";
import axios from "axios";
import { notFound } from "next/navigation";

export const generateMetadata = async ({
  params,
}: { params: Promise<{ projectId: number }>}): Promise<Metadata> => {
  const { projectId } = await params

  try {
    const response = await axios.get("/api/projects/projectname", {
      params: { projectId },
    });

    const projectName = response.data.name;

    return {
      title: `${projectName} | Valinhall`,
    };
  } catch (error) {
    console.error("Error fetching project name:", error);
    notFound();
  }
};