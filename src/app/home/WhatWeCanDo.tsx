import Image from "next/image";
import SectionHeader from "./SectionHeader";
import Box from "@/app/home/Box";
import { description } from "@/components/chart-area-interactive";

export default function WhatWeCanDo() {
  const points = [
    {
      title: "Code Security",
      description:
        "Integrate Valinhall into your pipeline and analyze your code on every push",
      imageSrc: "/assets/code_security.png",
    },
    {
      title: "Comprehensive Scanning",
      description:
        "Find vulnerabilities in your live websites and their subdomains all at once",
    },
    {
      title: "AI Penetration Testing",
      description: "On-demand, regardless of your company size",
    },
    {
      title: "User-Friendly Interface",
      description:
        "Friendly interface that doesn't bombard you with security jargon (almost)",
    },
  ];

  return (
    <div className="flex flex-col items-center justify-center relative">
      <SectionHeader
        text="what we can do"
        className="mt-18 mb-18 w-full px-6"
      />
      <div>
        {points.map((point, index) => (
          <div
            key={index}
            className="flex items-center justify-between mb-12 gap-3"
          >
            <div className="flex flex-col items-start w-2/3 gap-2">
              <h2 className="text-3xl font-medium text-center font-[family-name:var(--font-belanosima)]">
                {point.title}
              </h2>
              <p className="text-left text-md">{point.description}</p>
            </div>
            {/* <Image
              src={point.imageSrc}
              alt={point.title}
              width={600}
              height={600}
              className="w-24 h-24 mb-4"
            /> */}
          </div>
        ))}
      </div>
    </div>
  );
}
