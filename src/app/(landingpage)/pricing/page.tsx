"use client";
import React, { useState } from "react";
import { Slider } from "@/components/ui/slider";

const PricingPage: React.FC = () => {
  const [apiCalls, setApiCalls] = useState(5000);

  const pricingDetails = [
    { range: "First 10,000", rate: "$0.00" },
    { range: "10,001 - 100,000", rate: "$0.05" },
    { range: "1,000,001 - 2,000,000", rate: "$0.10" },
  ];

  return (
    <div className="text-white min-h-screen mt-10 py-10 px-6 font-[family-name:var(--font-fira-code)]">
      <div className="max-w-5xl mx-auto text-center">
        <h1 className="text-5xl font-bold mb-2 font-[family-name:var(--font-belanosima)] uppercase">
          Pay only for what you use
        </h1>
        <p className="text-gray-400 mb-8 text-lg">
          Transparent, usage-based pricing that scales with your business.
        </p>

        <div className="mb-8">
          <label
            htmlFor="apiCalls"
            className="block text-sm font-medium text-gray-300 mb-2"
          >
            Estimate your cost
          </label>
          <Slider
            id="apiCalls"
            defaultValue={[apiCalls]}
            min={1000}
            max={1000000}
            step={1000}
            onValueChange={(value) => setApiCalls(value[0])}
            className="w-full my-2"
          />
          <p className="text-sm text-gray-400">
            Monthly API calls: {apiCalls.toLocaleString()}
          </p>
        </div>

        <div className="bg-black p-6 rounded-xl border border-gray-700">
          <h3 className="text-xl font-semibold mb-4">
            Usage-based pricing details
          </h3>
          <table className="w-full text-left">
            <thead>
              <tr className="text-gray-400 border-b border-gray-700">
                <th className="py-2">Monthly API calls</th>
                <th className="py-2">Rate per call</th>
              </tr>
            </thead>
            <tbody>
              {pricingDetails.map((item, idx) => (
                <tr key={idx} className="border-b border-gray-800">
                  <td className="py-2">{item.range}</td>
                  <td className="py-2">{item.rate}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default PricingPage;
