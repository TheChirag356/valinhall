import { Separator } from "@/components/ui/separator";
import clsx from "clsx";

type SectionHeaderProps = {
  text: string;
  className?: string;
};

export default function SectionHeader({ text, className }: SectionHeaderProps) {
  return (
    <div
      className={clsx(
        "mx-4 flex items-center justify-center whitespace-nowrap font-[family-name:var(--font-fira-code)] uppercase relative hover:-translate-x-1/3 transition-all duration-300 ease-in-out",
        className
      )}
    >
      <Separator className="w-1/2" />
      <span className="px-4">/ {text}</span>
      <Separator className="w-1/2" />
    </div>
  );
}
