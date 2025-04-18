"use client";
import { AppSidebar } from "@/components/app-sidebar";
import { ChartAreaInteractive } from "@/components/chart-area-interactive";
import { DataTable } from "@/components/data-table";
import { SectionCards } from "@/components/section-cards";
import { SiteHeader } from "@/components/site-header";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";

import { useProjectStore } from '@/store/useProjectStore'


export default function Page({
  children,
  overview,
  liveuritesting,
  staticanalysis,
}: {
  children: React.ReactNode; // <- fallback/default route content
  overview: React.ReactNode;
  liveuritesting: React.ReactNode;
  staticanalysis: React.ReactNode;
}) {
  const { selectedNav, setSelectedNav } = useProjectStore()
  return (
    <SidebarProvider
      style={
        {
          "--sidebar-width": "calc(var(--spacing) * 72)",
          "--header-height": "calc(var(--spacing) * 12)",
        } as React.CSSProperties
      }
    >
      <AppSidebar variant="inset" />
      {overview}
    </SidebarProvider>
  );
}
