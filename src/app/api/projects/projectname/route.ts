import { NextRequest, NextResponse } from "next/server";
import axios from "axios";

export async function GET(req: NextRequest) {
    const { searchParams } = new URL(req.url);
    const projectId = searchParams.get("projectId");

    if (!projectId) {
        return NextResponse.json({ error: "Project ID is required" }, { status: 400 });
    }

    try {
        const response = await axios.get(
            `${process.env.NEXT_PUBLIC_API_URL}/projects/${projectId}`
        );

        return NextResponse.json(response.data);
    } catch (error) {
        console.error("Error fetching project data:", error);
        return NextResponse.json(
            { error: "Failed to fetch project data" },
            { status: 500 }
        );
    }
}
