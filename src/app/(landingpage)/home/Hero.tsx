import Image from "next/image";

export default function Hero() {
  return (
    <div className="flex flex-col items-center justify-center h-dvh mx-10 gap-16 relative">
      <div className="flex flex-col items-center justify-center">
        <div className="font-[family-name:var(--font-belanosima)] text-white text-2xl">
          welcome to
        </div>
        <div className="font-[family-name:var(--font-belanosima)] text-white text-6xl md:text-9xl font-bold uppercase hover:drop-shadow-lg transition-all duration-300 ease-in-out">
          Valinhall
        </div>
      </div>
      <div className="font-[family-name:var(--font-fira-code)] text-black dark:text-white text-lg md:text-xl flex flex-col gap-5 text-center">
        find vulnerabilities in your web applications.
        <div className="flex justify-center gap-5">
          <button className="border-1 px-4 py-3 rounded-full text-sm hover:bg-white hover:text-black transition-all duration-100 ease-in-out">
            audit now
          </button>
          <button className="border-1 px-4 py-3 rounded-full text-sm">
            text us!
          </button>
        </div>
      </div>
      <div className="absolute z-10 -bottom-15 -right-210 sm:-right-190 md:-right-180 lg:-right-100">
        <Image alt="illustration" src="/illustration.svg" width="1000" height={50} className=""></Image>
      </div>
    </div>
  );
}
