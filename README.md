# Epic Stack OAuth 2.0 example

This demonstrates how to add an OAuth 2.0 provider to your Epic Stack
application. It uses GitHub, but the changes would be very similar for any other
OAuth 2.0 provider with a
[`remix-auth` strategy](https://github.com/sergiodxa/remix-auth/discussions/111).

The easiest way to review the changes is to look at
[the commits](https://github.com/kentcdodds/epic-github-auth/commits). Here are
the highlights:

1. Install `remix-auth-github` and setup a GitHub app as documented in
   `remix-auth-github`
1. Add environment variables for the GitHub app's client ID and client secret
1. Add the `GitHubStrategy` to the available strategies for your authenticator.
1. Add a button to login with GitHub to the login page. It should post to
   `/auth/github`.
1. If no user exists for the GitHub email, set the onboardingEmail and redirect
   the user to onboarding. Otherwise, do the same thing you do when a user signs
   in with a password.
1. Add an action on a route to handle the `/auth/github` that calls
   `authenticate` with the `GitHubStrategy`.
1. Add a loader on a route for the `/auth/github/callback` GitHub callback. It
   should call `authenticate` with the `GitHubStrategy` again. Do the same thing
   to handle 2FA that we do for verifying password login.
