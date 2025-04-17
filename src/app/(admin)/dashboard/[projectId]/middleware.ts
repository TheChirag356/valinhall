// // middleware.ts
// import { NextRequest, NextResponse } from 'next/server'

// // Adjust this function to fetch project data from your DB
// async function getProjectOwner(projectId: string) {
//     // Mock logic — replace with actual DB query
//     const mockDB = {
//         '123': 'user1',
//         '456': 'user2',
//     }

//     return mockDB[projectId]
// }

// export async function middleware(request: NextRequest) {
//     const { pathname } = request.nextUrl
//     const projectIdMatch = pathname.match(/^\/dashboard\/([^/]+)$/)

//     if (!projectIdMatch) {
//         return NextResponse.next()
//     }

//     const projectId = projectIdMatch[1]

//     // Replace this with your actual auth logic
//     const userId = request.headers.get('x-user-id') // or from a JWT/cookie/session

//     if (!userId) {
//         return NextResponse.redirect(new URL('/login', request.url))
//     }

//     const projectOwner = await getProjectOwner(projectId)

//     if (projectOwner !== userId) {
//         return NextResponse.redirect(new URL('/unauthorized', request.url))
//     }

//     return NextResponse.next()
// }

// export const config = {
//     matcher: ['/dashboard/:path*'],
// }
