import Link from "next/link";

export default function Navbar() {
  return (
    <div className="h-12 fixed top-0 left-0 z-50 text-white font-[family-name:var(--font-fira-code)] flex items-center justify-center px-3 py-2 gap-6 w-full">
      <NavItem text="home" href="/" />
      <NavItem text="pricing" href="/pricing" />
      <NavItem text="contact" href="/contact" />
      <NavItem text="login" href="/login" />
    </div>
  );
}

function NavItem({ text, href }: { text: string; href?: string }) {
  return (
    <Link
      href={href || "/login"}
      className="backdrop-blur-lg rounded-sm px-4 py-1"
    >
      {text}
    </Link>
  );
}
