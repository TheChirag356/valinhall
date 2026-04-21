import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { drizzle } from 'drizzle-orm/d1';
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, BETTER_AUTH_SECRET } from '$env/static/private';
import * as schema from './db/schema';

// Configuration for providers and secrets
const authConfig = {
	socialProviders: {
		github: {
			clientId: GITHUB_CLIENT_ID,
			clientSecret: GITHUB_CLIENT_SECRET
		}
	},
	secret: BETTER_AUTH_SECRET
};

// export const auth = betterAuth({
// 	database: { dialect: 'sqlite', type: 'sqlite' },
// 	...authConfig
// });

export function createAuth(d1: any, baseURL: string = "http://localhost:5173") {
	return betterAuth({
		database: drizzleAdapter(drizzle(d1, { schema }), { provider: 'sqlite' }),
        baseURL,
		...authConfig
	});
}
