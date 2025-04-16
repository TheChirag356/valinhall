import Image from "next/image";

export default function Hero() {
  return (
    <div className="flex flex-col items-center justify-center h-dvh mx-10 gap-20 relative">
      <div className="flex flex-col items-center justify-center">
        <div className="font-[family-name:var(--font-belanosima)] text-white text-2xl">
          welcome to
        </div>
        <div className="font-[family-name:var(--font-belanosima)] text-white text-9xl font-bold uppercase hover:drop-shadow-lg transition-all duration-300 ease-in-out">
          Valinhall
        </div>
      </div>
      <div className="font-[family-name:var(--font-fira-code)] text-black dark:text-white text-xl flex flex-col gap-5">
        find vulnerabilities in your web applications.
        <div className="flex justify-center gap-5">
          <button className="border-1 px-4 py-3 rounded-full text-lg hover:bg-white hover:text-black transition-all duration-100 ease-in-out">
            audit now
          </button>
          <button className="border-1 px-4 py-3 rounded-full text-lg">
            text us!
          </button>
        </div>
      </div>
      <div className="absolute z-10 -bottom-20 -right-100">
        <Image alt="illustration" src="/illustration.svg" width="1000" height={50} className=""></Image>
      </div>
    </div>
  );
}
