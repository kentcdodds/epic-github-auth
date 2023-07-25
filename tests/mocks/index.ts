import { rest } from 'msw'
import { setupServer } from 'msw/node'
import closeWithGrace from 'close-with-grace'
import { requiredHeader, writeEmail } from './utils.ts'
import { faker } from '@faker-js/faker'

const handlers = [
	process.env.REMIX_DEV_HTTP_ORIGIN
		? rest.post(`${process.env.REMIX_DEV_HTTP_ORIGIN}ping`, req =>
				req.passthrough(),
		  )
		: null,

	// feel free to remove this conditional from the mock once you've set up resend
	process.env.RESEND_API_KEY
		? rest.post(`https://api.resend.com/emails`, async (req, res, ctx) => {
				requiredHeader(req.headers, 'Authorization')
				const body = await req.json()
				console.info('🔶 mocked email contents:', body)

				await writeEmail(body)

				return res(
					ctx.json({
						id: faker.string.uuid(),
						from: body.from,
						to: body.to,
						created_at: new Date().toISOString(),
					}),
				)
		  })
		: null,
	rest.post('https://github.com/login/oauth/access_token', (req, res, ctx) => {
		return res(
			ctx.body(
				new URLSearchParams({
					access_token: '__MOCK_ACCESS_TOKEN__',
					token_type: '__MOCK_TOKEN_TYPE__',
				}).toString(),
			),
		)
	}),
	rest.get('https://api.github.com/user', (req, res, ctx) => {
		return res(
			ctx.json({
				login: 'mocked-login',
				id: 123456789,
				name: 'Mocked User',
				avatar_url: 'https://github.com/ghost.png',
				emails: ['mock@example.com'],
			}),
		)
	}),
	rest.get('https://api.github.com/user/emails', (req, res, ctx) => {
		return res(ctx.json([{ email: 'mock@example.com' }]))
	}),
].filter(Boolean)

const server = setupServer(...handlers)

server.listen({ onUnhandledRequest: 'warn' })
console.info('🔶 Mock server installed')

closeWithGrace(() => {
	server.close()
})
