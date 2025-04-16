"use client";
import React, { useState } from "react";
import { Slider } from "@/components/ui/slider";

const PricingPage: React.FC = () => {
  const [apiCalls, setApiCalls] = useState(5000);

  const tiers = [
    {
      name: "Starter",
      price: "$0.00",
      features: [
        "Up to 10,000 API calls/month",
        "Basic analytics",
        "Community support",
        "Standard rate limiting",
      ],
    },
    {
      name: "Growth",
      price: "$49.00",
      features: [
        "Up to 100,000 API calls/month",
        "Advanced analytics",
        "Priority support",
        "Higher rate limits",
        "Team access",
        "Custom domains",
      ],
    },
    {
      name: "Scale",
      price: "$199.00",
      features: [
        "Up to 1,000,000 API calls/month",
        "Enterprise analytics",
        "24/7 support",
        "Highest rate limits",
        "Team access",
        "Custom domains",
        "SLA guarantee",
        "Dedicated account manager",
      ],
    },
  ];

  const pricingDetails = [
    { range: "First 10,000", rate: "$0.01" },
    { range: "10,001 - 100,000", rate: "$0.008" },
    { range: "100,001 - 1,000,000", rate: "$0.006" },
    { range: "1,000,001+", rate: "$0.004" },
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

        <div className="mb-4">
          <button className="bg-black text-white py-2 px-4 rounded-l">
            Monthly
          </button>
          <button className="bg-[#101010] text-gray-300 py-2 px-4 rounded-r">
            Annually (Save 20%)
          </button>
        </div>

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

        <div className="grid md:grid-cols-3 gap-6 mb-10">
          {tiers.map((tier) => (
            <div
              key={tier.name}
              className="bg-black p-6 rounded-xl border border-gray-700"
            >
              <h2 className="text-xl font-semibold mb-2">{tier.name}</h2>
              <p className="text-2xl font-bold mb-4">
                {tier.price}
                <span className="text-base font-medium"> /mo</span>
              </p>
              <ul className="text-left text-sm space-y-2">
                {tier.features.map((feature, i) => (
                  <li key={i}>✓ {feature}</li>
                ))}
              </ul>
              <button className="mt-6 w-full bg-white text-black py-2 rounded-md font-medium hover:bg-gray-200">
                Get Started
              </button>
            </div>
          ))}
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
