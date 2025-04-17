"use client";
import Image from "next/image";
import React, { useEffect, useState } from "react";

export default function Footer() {
  const [time, setTime] = useState("");

  useEffect(() => {
    const updateTime = () => {
      const formattedTime = new Date().toLocaleString("en-US", {
        timeZone: "Asia/Kolkata",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
      setTime(formattedTime);
    };

    updateTime(); // initial call
    const interval = setInterval(updateTime, 1000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="text-white p-4 text-center flex items-start justify-between font-[family-name:var(--font-fira-code)] h-26 relative overflow-hidden">
      <p>@Valinhall</p>
      <p className="hidden md:block">{`Time → ${time || "Loading..."}`}</p>
      <p>contact@valinhall.xyz</p>
      <Image
        src={"/illustration3.svg"}
        alt="footer illustration"
        width={500}
        height={500}
        className="absolute md:left-1/3 top-16 animate-spin"
      ></Image>
    </div>
  );
}
