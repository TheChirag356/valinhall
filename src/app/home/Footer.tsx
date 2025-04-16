"use client"; // if you're using app directory (Next.js 13+)

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
    <footer className="text-white p-4 text-center flex items-center justify-between">
      <p>@Valinhall</p>
      <p>{`Time → ${time || "Loading..."}`}</p>
      <p>contact@valinhall.xyz</p>
    </footer>
  );
}
