export default function SectionHeader({ text }: { text: string }) {
  return (
    <div className="mx-4 flex items-center font-[family-name:var(--font-fira-code)] uppercase">
      / {text}
    </div>
  );
}
