"use client";

import data from "../../data.json";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { DataTable } from "@/components/data-table";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
} from "@/components/ui/form";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { columns, ApiTest } from "@/components/columns";

export default function LiveURITestingPage() {
  const [step, setStep] = useState(0);

  const totalSteps = 2;
  const [name, setName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const form = useForm();

  const {
    handleSubmit,

    control,

    reset,
  } = form;

  const onSubmit = async (formData: unknown) => {
    if (step < totalSteps - 1) {
      setStep(step + 1);
    } else {
      console.log(formData);

      setStep(0);

      reset();

      toast.success("Form successfully submitted");
    }
  };

  const handleBack = () => {
    if (step > 0) {
      setStep(step - 1);
    }
  };

  return (
    <div className="space-y-4 mt-8">
      <div className="flex items-center justify-center">
        {Array.from({ length: totalSteps }).map((_, index) => (
          <div key={index} className="flex items-center">
            <div
              className={cn(
                "w-4 h-4 rounded-full transition-all duration-300 ease-in-out",

                index <= step ? "bg-primary" : "bg-primary/30",

                index < step && "bg-primary"
              )}
            />

            {index < totalSteps - 1 && (
              <div
                className={cn(
                  "w-8 h-0.5",

                  index < step ? "bg-primary" : "bg-primary/30"
                )}
              />
            )}
          </div>
        ))}
      </div>

      <Card className="shadow-sm">
        <CardHeader>
          <CardTitle className="text-lg">
            We would like to know a few things before we begin Live URI Testing
          </CardTitle>

          <CardDescription>Step {step + 1}</CardDescription>
        </CardHeader>

        <CardContent>
          {step === 0 && (
            <Form {...form}>
              <form onSubmit={handleSubmit(onSubmit)} className="grid gap-y-4">
                <FormField
                  key="jbLuSbMc"
                  control={control}
                  name="jbLuSbMc"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Enter your OpenAPI Spec File</FormLabel>

                      <Input
                        id="fileUpload"
                        type="file"
                        className="hidden"
                        onChange={(e) => setFile(e.target.files?.[0] || null)}
                      />
                      {file && (
                        <p className="mt-2 text-sm text-green-600">
                          File: {file.name}
                        </p>
                      )}

                      <FormDescription></FormDescription>
                    </FormItem>
                  )}
                />

                <div className="flex justify-between">
                  <Button
                    type="button"
                    className="font-medium"
                    size="sm"
                    onClick={handleBack}
                    disabled={step === 0}
                  >
                    Back
                  </Button>

                  <Button type="submit" size="sm" className="font-medium">
                    {step ? "Submit" : "Next"}
                  </Button>
                </div>
              </form>
            </Form>
          )}

          {step === 1 && (
            <Form {...form}>
              <form onSubmit={handleSubmit(onSubmit)} className="grid gap-y-4">
                <FormField
                  key="UW9NzH1o"
                  control={control}
                  name="UW9NzH1o"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Enter your live production URI</FormLabel>

                      <FormControl>
                        <Input {...field} placeholder="" autoComplete="off" />
                      </FormControl>

                      <FormDescription></FormDescription>
                    </FormItem>
                  )}
                />

                <div className="flex justify-between">
                  <Button
                    type="button"
                    className="font-medium"
                    size="sm"
                    onClick={handleBack}
                    disabled={Number(step) === 0}
                  >
                    Back
                  </Button>

                  <Button type="submit" size="sm" className="font-medium">
                    {step === 1 ? "Submit" : "Next"}
                  </Button>
                </div>
              </form>
            </Form>
          )}
        </CardContent>
      </Card>

      <DataTable columns={columns} data={data} />
    </div>
  );
}
