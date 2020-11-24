// Handle requests to /api/auth/signin
import oAuthSignin from '../lib/signin/oauth'
import emailSignin from '../lib/signin/email'
import logger from '../../lib/logger'

export default async (req, res, options, done) => {
  const {
    provider: providerName,
    providers,
    baseUrl,
    basePath,
    adapter,
    callbacks,
    csrfToken,
    redirect
  } = options
  const provider = providers[providerName]
  const { type } = provider

  if (!type) {
    res.status(500).end(`Error: Type not specified for ${provider}`)
    return done()
  }

  const _baseUrl = function(){
    if(process.env.MULTITENANT == "true"){
      let protocol = 'http'
      if( (req.headers.referer && req.headers.referer.split("://")[0] == 'https') || (req.headers['X-Forwarded-Proto'] && req.headers['X-Forwarded-Proto'] === 'https')){
        protocol = 'https'
      }
      return protocol + "://" + req.headers.host + `${basePath}`
    } else {
      return `${baseUrl}${basePath}`
    }
  }

  // Adding to handle multi tenant solutions where the base url changes


  if (type === 'oauth' && req.method === 'POST') {
    oAuthSignin(provider, csrfToken, (error, oAuthSigninUrl) => {
      if (error) {
        logger.error('SIGNIN_OAUTH_ERROR', error)
        return redirect(_baseUrl() + `/error?error=OAuthSignin`)
      }

      return redirect(oAuthSigninUrl)
    })
  } else if (type === 'email' && req.method === 'POST') {
    if (!adapter) {
      logger.error('EMAIL_REQUIRES_ADAPTER_ERROR')
      return redirect(_baseUrl() + `/error?error=Configuration`)
    }
    const { getUserByEmail } = await adapter.getAdapter(options)

    // Note: Technically the part of the email address local mailbox element
    // (everything before the @ symbol) should be treated as 'case sensitive'
    // according to RFC 2821, but in practice this causes more problems than
    // it solves. We treat email addresses as all lower case. If anyone
    // complains about this we can make strict RFC 2821 compliance an option.
    const email = req.body.email ? req.body.email.toLowerCase() : null

    // If is an existing user return a user object (otherwise use placeholder)
    const profile = await getUserByEmail(email) || { email }
    const account = { id: provider.id, type: 'email', providerAccountId: email }

    // Check if user is allowed to sign in
    try {
      const signinCallbackResponse = await callbacks.signIn(profile, account, { email, verificationRequest: true })
      if (signinCallbackResponse === false) {
        return redirect(_baseUrl() + `/error?error=AccessDenied`)
      }
    } catch (error) {
      if (error instanceof Error) {
        return redirect(_baseUrl() + `/error?error=${encodeURIComponent(error)}`)
      } else {
        return redirect(error)
      }
    }

    try {
      await emailSignin(email, provider, options)
    } catch (error) {
      logger.error('SIGNIN_EMAIL_ERROR', error)
      return redirect(_baseUrl() + `/error?error=EmailSignin`)
    }
    return redirect(_baseUrl() + `/verify-request?provider=${encodeURIComponent(
      provider.id
    )}&type=${encodeURIComponent(provider.type)}`)
  } else {
    return redirect(_baseUrl() + `_baseUrl() + /signin`)
  }
}
