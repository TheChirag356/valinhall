"use client";
import { TextGenerateEffect } from "@/components/ui/text-generate-effect";

const words = `Valinhall lets you move faster by making sure your application is secure while you focus on what truly matters. Learn how Valinhall can help make your development cycles more efficient with better security.
`;

export default function Message() {
  return <div className="flex flex-col items-center justify-center relative mt-18 mb-18 w-full px-32">
      <TextGenerateEffect words={words} className="text-xl font-medium" />
  </div>;
}
