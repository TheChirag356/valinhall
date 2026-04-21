import { createAuth } from "$lib/server/auth";
import type { RequestHandler } from "./$types";

export const GET: RequestHandler = ({ request, platform, url }) => {
    if (!platform?.env) return new Response("Missing env", { status: 500 });
    return createAuth(platform.env.DB, url.origin).handler(request);
};

export const POST: RequestHandler = ({ request, platform, url }) => {
    if (!platform?.env) return new Response("Missing env", { status: 500 });
    return createAuth(platform.env.DB, url.origin).handler(request);
};
