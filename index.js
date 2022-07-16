const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const axios = require('axios');
const { Issuer, generators, TokenSet, custom } = require('openid-client');
const OAUTH2_CONFIGURATIONS = {
    TWITTER: {
      issuer: 'https://twitter.com',
      authorization_endpoint: 'https://twitter.com/i/oauth2/authorize',
      token_endpoint: 'https://api.twitter.com/2/oauth2/token',
      revoke_endpoint: 'https://api.twitter.com/2/oauth2/revoke',
      userinfo_endpoint: 'https://api.twitter.com/2/users/me',
      client_id: 'RmU2TjFxU1N5RWttWUJIUF9XQVo6MTpjaQ',
      client_secret: '0nACd07lvLlkPypcEchE6HtPDXSp_Q9xQ_kdWhXf9XEbO2Tdls',
      redirect_uri: 'http://localhost:3000/auth/callback',
      client_type: 'CONFIDENTIAL', // or 'PUBLIC'
    }
  };

const config = OAUTH2_CONFIGURATIONS.TWITTER;
const issuer = new Issuer({
  issuer: config.issuer,
  authorization_endpoint: config.authorization_endpoint,
  token_endpoint: config.token_endpoint,
});
const client = issuer.Client({
  client_id: config.client_id,
  client_secret: config.client_secret,
});
client[custom.http_options] = (url, options) => {
  console.log('>>>>>>> OpenClient Request >>>>>>>', url.href, {options});
  return { timeout: 0 };
}

const app = express();
app.use(session({
  name: 'session',
  secret: [crypto.randomBytes(32).toString('hex')],
  resave: true,
  saveUninitialized: true,
}));

app.get('/', (req, res) => {
  res.send('<a href="/auth/login">LOGIN</a>');
});

app.get('/private', (req, res, next) => {
  if (!req.session.userInfo) {
    return res.status(401).send('unauthorized');
  } else if (req.session.tokenSet.expired()) {
    try {
      const refreshedTokenSet = await req.app.authClient.refresh(req.session.tokenSet);
      req.session.tokenSet = refreshedTokenSet;
    } catch(e) {
      return next(e);
    }

    // validate the token, check if http call is made
    try {
      const resp = await client.validateIdToken.call(client, req.session.tokenSet);
      console.log('>>>> validating token', resp);
    } catch(err) {
      return next(new Error("Bad Token in Auth Cookie!"));
    }

    return res.json(req.session.userInfo);
  }
})

// dependency: client,config,generators,axios
app.get('/auth/login', async (req, res) => {
  if (!req.session.tokenSet) { // if not loggedin
    const state = generators.state();
    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const authRedirectUrl = client.authorizationUrl({
      redirect_uri: config.redirect_uri,
      response_type: 'code',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    });

    req.session.state = state;
    req.session.codeVerifier = codeVerifier;
    req.session.loginRedirectTo = req.queryString.redirectTo || '/private';
    
    res.redirect(authRedirectUrl); // will redirect to /auth/callback
  } else {
    return res.redirect(req.session.loginRedirectTo || '/');
  }
});

app.get('/auth/callback', async (req, res) => {
  const state = req.session.state;
  const codeVerifier = req.session.codeVerifier;
  const params = client.callbackParams(req);
  // POST call to token_endpoint
  try {
    const tokenSet = await client.oauthCallback( 
      config.redirect_uri, 
      params, 
      { code_verifier: codeVerifier, state }, 
      { exchangeBody: { client_id: config.client_id } 
    });
    console.log('received and validated tokens %j', tokenSet);
    req.session.tokenSet = tokenSet;
  } catch(e) {
    return next(e);
  }

  // POST call to userinfo_endpoint
  try {
    const resp = await axios.get(config.userinfo_endpoint, {
      headers: { 
        Accept: 'application/json',
        Authorization: `Bearer ${req.session.tokenSet.access_token}` 
      }
    });
    req.session.userInfo = resp.data;
    console.log('received userInfo %j', resp.data);
    return res.redirect(req.session.loginRedirectTo);
  } catch(e) {
    return next(e);
  }
});

app.get('/auth/logout', async (req, res, next) => {
  try {
    const resp = await client.revoke(req.session.tokenSet.access_token);
    req.session.destroy();
    return res.send('logout');
  } catch(e) {
    console.error('error revoking access_token', e);
  }
});

app.listen(3000, () => console.log('Listening on port 3000'));