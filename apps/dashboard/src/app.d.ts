// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces
declare global {
	namespace App {
		// interface Error {}
		interface Locals {
			user: import("better-auth").User | null;
			session: import("better-auth").Session | null;
		}
		// interface PageData {}
		// interface PageState {}
		interface Platform {
			env: {
				DB: D1Database;
				BETTER_AUTH_SECRET: string;
				GITHUB_CLIENT_ID: string;
				GITHUB_CLIENT_SECRET: string;
				GOOGLE_CLIENT_ID: string;
				GOOGLE_CLIENT_SECRET: string;
			}
		}
	}
}

export {};
