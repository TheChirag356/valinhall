import { NextRequest, NextResponse } from "next/server";
import axios, { isAxiosError } from "axios";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const userId = searchParams.get("userId");

  if (!userId) {
    return NextResponse.json({ error: "User ID is required" }, { status: 400 });
  }

  try {
    const response = await axios.get(`${process.env.NEXT_PUBLIC_API_URL}/projects`, {
      params: { userId },
    });

    return NextResponse.json(response.data);
  } catch (error) {
    if (isAxiosError(error)) {
      console.error("Axios error fetching projects:", error.response?.data || error.message);
    } else {
      console.error("Unexpected error fetching projects:", error);
    }

    return NextResponse.json(
      { error: "Failed to fetch projects from backend" },
      { status: 500 }
    );
  }
}