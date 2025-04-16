import React from "react";
import { BackgroundBeamsWithCollision } from "@/components/ui/background-beams-with-collision";

export default function NotFound() {
  return (
    <BackgroundBeamsWithCollision className="flex flex-col items-center justify-center h-screen w-full">
      <h2 className="text-2xl relative z-20 md:text-4xl lg:text-9xl font-bold text-center text-black dark:text-white font-[family-name:var(--font-belanosima)]">
        404
      </h2>
      <p className="font-[family-name:var(--font-fira-code)]">page not found</p>
    </BackgroundBeamsWithCollision>
  );
}
