"use client";
import { AppSidebar } from "@/components/app-sidebar";
import { ChartAreaInteractive } from "@/components/chart-area-interactive";
import { SectionCards } from "@/components/section-cards";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useState } from "react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogClose,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { FileUpload } from "@/components/ui/file-upload";

export default function OverviewPage() {
  const [name, setName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [files, setFiles] = useState<File[]>([]);
  const handleFileUpload = (files: File[]) => {
    setFiles(files);
    console.log(files);
  };
  return (
    <div className="flex flex-1 flex-col justify-items-start items-center p-8">
      <h1 className="font-[family-name:var(--font-belanosima)] text-3xl mb-2">
        Welcome to Valinhall! This is your overview page.
      </h1>
      <div className="font-[family-name:var(--font-fira-code)]">
        Here you can find a summary of your project, including key metrics and
        insights.
      </div>

      <div className="w-full max-w-4xl mx-auto min-h-96 border border-dashed border-neutral-200 dark:border-neutral-800 rounded-lg">
      <FileUpload onChange={handleFileUpload} />
    </div>
    </div>
  );
}
