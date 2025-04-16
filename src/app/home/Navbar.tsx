import Link from "next/link";

export default function Navbar() {
  return (
    <div className="h-12 fixed top-0 left-0 z-50 text-white font-[family-name:var(--font-fira-code)] flex items-center justify-center px-3 py-2 gap-6 w-full">
      <NavItem text="pricing" />
      <NavItem text="contact" />
      <NavItem text="login" />
    </div>
  );
}

function NavItem({ text }: { text: string }) {
  return (
    <Link href="/login" className="backdrop-blur-lg rounded-sm px-4 py-1">
      {text}
    </Link>
  );
}
