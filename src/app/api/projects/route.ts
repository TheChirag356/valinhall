import { NextRequest, NextResponse } from "next/server";
import axios from "axios";

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
  } catch (error: any) {
    console.error("Error fetching projects:", error.message || error);
    return NextResponse.json(
      { error: "Failed to fetch projects from backend" },
      { status: 500 }
    );
  }
}
