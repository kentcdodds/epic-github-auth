import { redirect, type DataFunctionArgs } from '@remix-run/node'
import { GitHubStrategy } from 'remix-auth-github'
import { authenticator } from '~/utils/auth.server.ts'
import { prisma } from '~/utils/db.server.ts'
import { invariantResponse } from '~/utils/misc.ts'
import { commitSession, getSession } from '~/utils/session.server.ts'
import { unverifiedSessionKey } from '../resources+/verify.tsx'
import { twoFAVerificationType } from '../settings+/profile.two-factor.tsx'

export async function loader({ request }: DataFunctionArgs) {
	const sessionId = await authenticator.authenticate(
		GitHubStrategy.name,
		request,
		{
			failureRedirect: '/login',
		},
	)

	const session = await prisma.session.findUnique({
		where: { id: sessionId },
		select: { userId: true, expirationDate: true },
	})
	invariantResponse(session, 'newly created session not found')

	const user2FA = await prisma.verification.findFirst({
		where: { type: twoFAVerificationType, target: session.userId },
		select: { id: true },
	})

	const cookieSession = await getSession(request.headers.get('cookie'))
	const keyToSet = user2FA ? unverifiedSessionKey : authenticator.sessionKey
	cookieSession.set(keyToSet, sessionId)

	const responseInit = {
		headers: {
			'Set-Cookie': await commitSession(cookieSession, {
				expires: session.expirationDate,
			}),
		},
	}
	if (user2FA) {
		return redirect('/login', responseInit)
	} else {
		throw redirect('/', responseInit)
	}
}
