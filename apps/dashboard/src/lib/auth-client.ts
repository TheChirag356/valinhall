import { createAuthClient } from 'better-auth/svelte';
export const { signIn, signUp, signOut, useSession } = createAuthClient({});
