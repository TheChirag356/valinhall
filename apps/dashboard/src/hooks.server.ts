import { createAuth } from "$lib/server/auth";
import { svelteKitHandler } from "better-auth/svelte-kit";
import { building } from "$app/environment";

export async function handle({ event, resolve }) {
	const env = event.platform?.env;
	if (!env?.DB) {
		return resolve(event);
	}
	
	const auth = createAuth(env.DB, event.url.origin);

	try {
		const session = await auth.api.getSession({ headers: event.request.headers });
		event.locals.user = session?.user ?? null;
		event.locals.session = session?.session ?? null;
	} catch (err) {
		event.locals.user = null;
		event.locals.session = null;
	}

    return svelteKitHandler({ event, resolve, auth, building });
}