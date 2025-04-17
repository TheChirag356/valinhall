"use client";

import * as React from "react";
import { Check, ChevronsUpDown } from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import axios from "axios";

type Project = {
  id: number;
  name: string;
};

// const response = await axios.get<Project[]>("/api/projectname", {
//   params: { userId: "12345" },
// });

// const projects = response.data;

const projects = [
  {
    id: 2353636,
    name: "HLNA",
  },
  {
    id: 8898697,
    name: "Valinhall",
  }
];

export default function Projects() {
  const [open, setOpen] = React.useState(false);
  const [value, setValue] = React.useState("");
  const [newProjectName, setNewProjectName] = React.useState("Project Name");
  const [newProjectDescription, setNewProjectDescription] = React.useState(
    "Project Description"
  );

  return (
    <div className="flex justify-center items-center flex-col relative h-dvh bg-[#e8e8e8] dark:bg-[#181818]">
      <div className="min-h-56 w-1/3 bg-black rounded-2xl flex flex-col justify-center items-center gap-4 p-6 border-1 border-[#262626]">
        <h1 className="font-[family-name:var(--font-belanosima)] dark:text-white">
          Choose an existing project
        </h1>
        <div>
          <Popover open={open} onOpenChange={setOpen}>
            <PopoverTrigger asChild>
              <Button
                variant="outline"
                role="combobox"
                aria-expanded={open}
                className="w-[200px] justify-between"
              >
                {value
                  ? projects.find((framework) => framework.id === id)?.name
                  : "Select your project..."}
                <ChevronsUpDown className="opacity-50" />
              </Button>
            </PopoverTrigger>
            <PopoverContent className="w-[200px] p-0">
              <Command>
                <CommandInput
                  placeholder="Search your projects..."
                  className="h-9"
                />
                <CommandList>
                  <CommandEmpty>No Project found.</CommandEmpty>
                  <CommandGroup>
                    {projects.map((framework) => (
                      <CommandItem
                        key={framework.id}
                        value={framework.name}
                        onSelect={(currentValue) => {
                          setValue(currentValue === value ? "" : currentValue);
                          setOpen(false);
                        }}
                      >
                        {framework.name}
                        <Check
                          className={cn(
                            "ml-auto",
                            value === framework.name
                              ? "opacity-100"
                              : "opacity-0"
                          )}
                        />
                      </CommandItem>
                    ))}
                  </CommandGroup>
                </CommandList>
              </Command>
            </PopoverContent>
          </Popover>
        </div>

        <Separator />
        <h1 className="font-[family-name:var(--font-belanosima)] dark:text-white">
          Or create a new one
        </h1>
        <div>
          <Dialog>
            <DialogTrigger asChild>
              <Button variant="outline">Create</Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[425px]">
              <DialogHeader>
                <DialogTitle>Create New Project</DialogTitle>
                <DialogDescription>
                  Create a new project to start using Valinhall.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="name" className="text-right">
                    Project Name
                  </Label>
                  <Input
                    id="name"
                    value={newProjectName}
                    className="col-span-3"
                    onChange={(e) => setNewProjectName(e.target.value)}
                  />
                </div>
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="name" className="text-right">
                  Project Description
                </Label>
                <Input
                  id="description"
                  value={newProjectDescription}
                  className="col-span-3"
                  onChange={(e) => setNewProjectDescription(e.target.value)}
                />
              </div>
              <DialogFooter>
                <Button type="submit">Let&apos;s Go</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>
    </div>
  );
}
