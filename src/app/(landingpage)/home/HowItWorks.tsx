import SectionHeader from "@/app/(landingpage)/home/SectionHeader";
import { CodeBlock } from "@/components/ui/code-block";
import Image from "next/image";

export default function HowItWorks() {
  const ReDos = [
    "function isValidInput(input) {",
    "  const pattern = /^([a-zA-Z]+)+$/;",
    "  return pattern.test(input);",
    "}",
  ];

  return (
    <div className="flex flex-col items-center justify-center relative">
      <SectionHeader text="how it works" className="mt-18 w-full px-6" />
      <div className="flex flex-col md:flex-row justify-center items-center w-7xl min-h-[26rem] mt-24 mb-24 gap-4 z-10">
        <div className="bg-black w-1/2 h-full rounded-md border-1 border-[#262626] p-6"></div>
        <div className="bg-black w-1/2 h-full rounded-md border-1 border-[#262626] p-6">
          <h1 className="font-[family-name:var(--font-belanosima)] text-2xl">
            Vulnerability Report
          </h1>
          <p>Regular Expression Denial of Service (ReDoS) vulnerability</p>
          <CodeBlock lines={ReDos} highlightLines={[3]} />
          <p className="text-yellow-400">
            {`Impact: Input like \`"a".repeat(10000) + "!"\` causes excessive
            backtracking in the regex engine, potentially freezing the event
            loop and leading to a denial of service.`}
          </p>
          <p className="text-green-400">
            {`Mitigation: Avoid nested quantifiers in regex patterns. Use safer
            patterns like \`/^[a-zA-Z]+$/\` or limit input length before applying
            regex.`}
          </p>
        </div>
      </div>
      <div className="absolute top-36 left-10">
        <Image
          src="/illustration2.svg"
          alt="illustration"
          width={200}
          height={200}
          className="z-1 spin duration-[5s] blur-2xl"
        ></Image>
      </div>
    </div>
  );
}
