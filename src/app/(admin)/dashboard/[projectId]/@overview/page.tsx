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

export default function OverviewPage() {
  const [name, setName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  return (
    <div className="flex flex-1 flex-col justify-items-start items-center p-8">
      <h1 className="font-[family-name:var(--font-belanosima)] text-3xl mb-2">
        Welcome to Valinhall! This is your overview page.
      </h1>
      <div className="font-[family-name:var(--font-fira-code)]">
        Here you can find a summary of your project, including key metrics and
        insights.
      </div>

      <div className="flex flex-col gap-4 mt-4 h-full max-w-2xl justify-center items-center">
          <Dialog>
            <DialogTrigger>Click To Upload OpenAPI Spec</DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Drag and Drop the file here</DialogTitle>
              </DialogHeader>
              <div className="mt-4 p-4 border border-dashed rounded-lg text-center">
                <label
                  htmlFor="fileUpload"
                  className="cursor-pointer text-white hover:underline"
                >
                  Click To Upload Spec
                </label>
                <p className="text-sm text-muted-foreground">or drag and drop</p>
                <Input
                  id="fileUpload"
                  type="file"
                  className="hidden"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                />
                {file && (
                  <p className="mt-2 text-sm text-green-600">File: {file.name}</p>
                )}
              </div>
            </DialogContent>
          </Dialog>
      </div>
    </div>
  );
}
