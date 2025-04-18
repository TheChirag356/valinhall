export async function GET() {
    const res = await fetch(`${process.env.NGROK_URL}/api/auth/github/authorize`)
    return new Response(await res.text())
}
