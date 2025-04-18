import { NextResponse, NextRequest } from "next/server";
import axios from "axios";

export async function POST(request: NextRequest) {
  try {
    // Parse the request body
    const body = await request.json();
    const { email, password } = body;
    
    if (!email || !password) {
      return NextResponse.json(
        { error: "Email and password are required" },
        { status: 400 }
      );
    }
    
    // Get the nginx URL from environment variables
    const nginxUrl = process.env.NGINX_URL;
    
    if (!nginxUrl) {
      return NextResponse.json(
        { error: "Server configuration error" },
        { status: 500 }
      );
    }
    
    // Make the axios request to the nginx server
    const response = await axios.post(`${nginxUrl}/api/auth/register`, {
      email,
      password
    });
    
    // Return the response from the nginx server
    return NextResponse.json(response.data);
  } catch (error) {
    console.error("Registration error:", error);
    return NextResponse.json(
      { error: "Failed to register user" },
      { status: 500 }
    );
  }
}