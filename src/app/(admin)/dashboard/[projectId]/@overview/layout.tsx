import { SiteHeader } from "@/components/site-header";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";

export default function OverviewLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <SidebarInset>
        <SiteHeader />
        {children}
    </SidebarInset>

  );
}