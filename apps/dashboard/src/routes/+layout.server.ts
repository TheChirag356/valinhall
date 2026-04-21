import { redirect } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ locals, url }) => {
	const isAuthPage = url.pathname.startsWith('/login') || url.pathname.startsWith('/api/auth');

	if (!locals.user && !isAuthPage) {
		throw redirect(302, '/login');
	}

	if (locals.user && url.pathname.startsWith('/login')) {
		throw redirect(302, '/');
	}

	return {
		user: locals.user,
		session: locals.session
	};
};
