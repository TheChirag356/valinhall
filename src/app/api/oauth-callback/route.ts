import axios from 'axios';
import { redirect } from 'next/navigation';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
    const url = request.nextUrl;

    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    if (!code || !state) {
        return NextResponse.json({ error: 'Missing code or state' }, { status: 400 });
    }

    let res = await axios.get(`https://92e2-49-205-174-188.ngrok-free.app/api/auth/github/callback?code=${code}&state=${state}`);
    return NextResponse.json(res, { status: 200 });
}
