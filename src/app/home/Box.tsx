import Image from "next/image";

export default function Box({ children }: { children: React.ReactNode }) {
  return (
    <div className="border border-gray-300 rounded">
      <div className="border-b border-gray-300 p-2 flex justify-between items-center">
        <div className="font-mono text-xs text-gray-500">[ FILE 1 ]</div>
        <div className="flex space-x-2">
          <span className="inline-block w-3 h-3 border border-gray-300 rounded-full"></span>
          <span className="inline-block w-3 h-3 border border-gray-300 rounded-full"></span>
          <span className="inline-block w-3 h-3 border border-gray-300 rounded-full"></span>
        </div>
      </div>
      <div className="p-4 bg-white">
        {children}
      </div>
    </div>
  );
}
