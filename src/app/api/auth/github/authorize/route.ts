export async function GET() {
    const res = await fetch("https://92e2-49-205-174-188.ngrok-free.app/api/auth/github/authorize")
    return new Response(res.body)
}