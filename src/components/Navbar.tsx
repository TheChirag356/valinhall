export default function Navbar() {
  return (
    <div className="h-12 fixed top-0 left-0 z-10 text-white font-[family-name:var(--font-fira-code)] flex items-center justify-center px-3 py-2 gap-6 w-full">
      <NavItem text="pricing" />
      <NavItem text="contact" />
      {/* <NavItem text="Login" /> */}
      <button className="border-1 px-3 py-1 rounded-xl text-lg bg-[#181818] hover:bg-white hover:text-black transition-all duration-100 ease-in-out">
        Login
      </button>
    </div>
  );
}

function NavItem({ text }: { text: string }) {
  return <div>{text}</div>;
}
