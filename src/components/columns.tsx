"use client"

import { ColumnDef } from "@tanstack/react-table"

// Define the data type
export type ApiTest = {
  testName: string
  method: string
  endpoint: string
  expectedStatus: number
  payload?: {
    header?: string
    type?: string
    status?: string
    target?: string
    limit?: string
    reviewer?: string
  }
}

// Define the column config
export const columns: ColumnDef<ApiTest>[] = [
  {
    accessorKey: "testName",
    header: "Test Name",
  },
  {
    accessorKey: "method",
    header: "Method",
  },
  {
    accessorKey: "endpoint",
    header: "Endpoint",
  },
  {
    id: "status",
    header: "Status",
    accessorFn: (row) => row.payload?.status ?? "N/A",
  },
  {
    id: "reviewer",
    header: "Reviewer",
    accessorFn: (row) => row.payload?.reviewer ?? "N/A",
  },
  {
    accessorKey: "expectedStatus",
    header: "Expected Status",
  },
]
