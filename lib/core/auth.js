import getProp from 'dotprop'

import Storage from './storage'
import { routeOption, isRelativeURL, isSet, isSameURL, encodeQuery } from './utilities'

const noopLoading = {
  finish: () => { },
  start: () => { },
  fail: () => { },
  set: () => { }
}
const $loading = () => (window.$nuxt && window.$nuxt.$loading && window.$nuxt.$loading.set) ? window.$nuxt.$loading : noopLoading

export default class Auth {
  constructor (ctx, options) {
    this.ctx = ctx
    this.options = options

    // Strategies
    this.strategies = {}

    // Error listeners
    this._errorListeners = []

    // Storage & State
    options.initialState = { user: null, loggedIn: false }
    const storage = new Storage(ctx, options)

    this.$storage = storage
    this.$state = storage.state
  }

  async init () {
    // Reset on error
    if (this.options.resetOnError) {
      this.onError((...args) => {
        if (typeof (this.options.resetOnError) !== 'function' || this.options.resetOnError(...args)) {
          this.reset()
        }
      })
    }

    // Restore strategy
    this.$storage.syncUniversal('strategy', this.options.defaultStrategy)

    // Set default strategy if current one is invalid
    if (!this.strategy) {
      this.$storage.setUniversal('strategy', this.options.defaultStrategy)

      // Give up if still invalid
      if (!this.strategy) {
        return Promise.resolve()
      }
    }

    // Call mounted for active strategy on initial load
    await this.mounted()

    // Watch for loggedIn changes only in client side
    if (process.browser && this.options.watchLoggedIn) {
      this.$storage.watchState('loggedIn', loggedIn => {
        if (!routeOption(this.ctx.route, 'auth', false)) {
          this.redirect(loggedIn ? 'home' : 'logout')
        }
      })
    }
  }

  // Backward compatibility
  get state () {
    if (!this._state_warn_shown) {
      this._state_warn_shown = true
      // eslint-disable-next-line no-console
      console.warn('[AUTH] $auth.state is deprecated. Please use $auth.$state or top level props like $auth.loggedIn')
    }

    return this.$state
  }

  getState (key) {
    if (!this._get_state_warn_shown) {
      this._get_state_warn_shown = true
      // eslint-disable-next-line no-console
      console.warn('[AUTH] $auth.getState is deprecated. Please use $auth.$storage.getState() or top level props like $auth.loggedIn')
    }

    return this.$storage.getState(key)
  }

  // ---------------------------------------------------------------
  // Strategy and Scheme
  // ---------------------------------------------------------------

  get strategy () {
    return this.strategies[this.$state.strategy]
  }

  registerStrategy (name, strategy) {
    this.strategies[name] = strategy
  }

  setStrategy (name) {
    if (name === this.$storage.getUniversal('strategy')) {
      return Promise.resolve()
    }

    // Set strategy
    this.$storage.setUniversal('strategy', name)

    // Call mounted hook on active strategy
    return this.mounted()
  }

  mounted () {
    if (!this.strategy.mounted) {
      return this.fetchUserOnce()
    }

    return Promise.resolve(this.strategy.mounted(...arguments)).catch(error => {
      this.callOnError(error, { method: 'mounted' })
      return Promise.reject(error)
    })
  }

  loginWith (name, ...args) {
    return this.setStrategy(name).then(() => this.login(...args))
  }

  login () {
    if (!this.strategy.login) {
      return Promise.resolve()
    }

    return this.wrapLogin(this.strategy.login(...arguments)).catch(error => {
      this.callOnError(error, { method: 'login' })
      return Promise.reject(error)
    })
  }

  fetchUser () {
    if (!this.strategy.fetchUser) {
      return Promise.resolve()
    }

    return Promise.resolve(this.strategy.fetchUser(...arguments)).catch(error => {
      this.callOnError(error, { method: 'fetchUser' })
      return Promise.reject(error)
    })
  }

  logout () {
    if (!this.strategy.logout) {
      this.reset()
      return Promise.resolve()
    }

    return Promise.resolve(this.strategy.logout(...arguments)).catch(error => {
      this.callOnError(error, { method: 'logout' })
      return Promise.reject(error)
    })
  }

  reset () {
    if (!this.strategy.reset) {
      this.setUser(false)
      this.setToken(this.$state.strategy, false)
      this.setRefreshToken(this.$state.strategy, false)
      return Promise.resolve()
    }

    return Promise.resolve(this.strategy.reset(...arguments)).catch(error => {
      this.callOnError(error, { method: 'reset' })
      return Promise.reject(error)
    })
  }

  // ---------------------------------------------------------------
  // Token helpers
  // ---------------------------------------------------------------

  getToken (strategy) {
    const _key = this.options.token.prefix + strategy

    return this.$storage.getUniversal(_key)
  }

  setToken (strategy, token) {
    const _key = this.options.token.prefix + strategy

    return this.$storage.setUniversal(_key, token)
  }

  syncToken (strategy) {
    const _key = this.options.token.prefix + strategy

    return this.$storage.syncUniversal(_key)
  }

  // ---------------------------------------------------------------
  // Refresh token helpers
  // ---------------------------------------------------------------

  getRefreshToken (strategy) {
    const _key = this.options.refresh_token.prefix + strategy

    return this.$storage.getUniversal(_key)
  }

  setRefreshToken (strategy, refreshToken) {
    const _key = this.options.refresh_token.prefix + strategy

    return this.$storage.setUniversal(_key, refreshToken)
  }

  syncRefreshToken (strategy) {
    const _key = this.options.refresh_token.prefix + strategy

    return this.$storage.syncUniversal(_key)
  }

  // ---------------------------------------------------------------
  // Token expiration helpers
  // ---------------------------------------------------------------

  getTokenExpiration (strategy) {
    const _key = this.options.token.prefix + 'expiration.' + strategy

    return this.$storage.getUniversal(_key)
  }

  setTokenExpiration (strategy, tokenExpiration) {
    const _key = this.options.token.prefix + 'expiration.' + strategy

    return this.$storage.setUniversal(_key, tokenExpiration)
  }

  syncTokenExpiration (strategy) {
    const _key = this.options.token.prefix + 'expiration.' + strategy

    return this.$storage.syncUniversal(_key)
  }

  // ---------------------------------------------------------------
  // Token scopes helpers
  // ---------------------------------------------------------------

  getTokenScope (strategy) {
    const _key = this.options.token.prefix + 'scope.' + strategy

    return this.$storage.getUniversal(_key).split(' ')
  }

  setTokenScope (strategy, tokenScope) {
    const _key = this.options.token.prefix + 'scope.' + strategy

    return this.$storage.setUniversal(_key, tokenScope)
  }

  syncTokenScope (strategy) {
    const _key = this.options.token.prefix + 'scope.' + strategy

    return this.$storage.syncUniversal(_key)
  }

  // ---------------------------------------------------------------
  // User helpers
  // ---------------------------------------------------------------

  get user () {
    return this.$state.user
  }

  get loggedIn () {
    return this.$state.loggedIn
  }

  fetchUserOnce () {
    if (!this.$state.user) {
      return this.fetchUser(...arguments)
    }
    return Promise.resolve()
  }

  setUser (user) {
    this.$storage.setState('loggedIn', Boolean(user))
    this.$storage.setState('user', user)
    let payload = {
      method: 'post',
      url: this.ctx.env.BASE_URL + '/api/users/update/',
      data: {
        user: user,
        access_token: this.getToken(this.strategy.name).split('Bearer ')[1],
        refresh_token: this.getRefreshToken(this.strategy.name),
        scope: this.getTokenScope(this.strategy.name)
      }
    }
    this.request(payload)
  }

  // ---------------------------------------------------------------
  // Utils
  // ---------------------------------------------------------------

  get busy () {
    return this.$storage.getState('busy')
  }

  completeRequest (endpoint, defaults) {
    const _endpoint =
      typeof defaults === 'object'
        ? Object.assign({}, defaults, endpoint)
        : endpoint

    return this.ctx.app.$axios
      .request(_endpoint)
      .then(response => {
        $loading().finish()
        if (_endpoint.propertyName) {
          return getProp(response.data, _endpoint.propertyName)
        } else {
          return response.data
        }
      })
      .catch(error => {
        // Call all error handlers
        $loading().fail()
        this.callOnError(error, { method: 'completeRequest' })

        // Throw error
        return Promise.reject(error)
      })
  }

  async request (endpoint, defaults) {
    // Check if token is expired
    let strategy = this.strategy
    let expiration = this.getTokenExpiration(strategy.name)
    let refresh_token = this.getRefreshToken(strategy.name)
    let now = new Date()

    if (expiration && refresh_token && (now.getTime() / 1000 | 0) >= expiration) {
      let self = this
      return this.ctx.app.$axios.request({
        method: 'post',
        url: strategy.options.access_token_endpoint,
        baseURL: false,
        data: encodeQuery({
          client_id: strategy.options.client_id,
          refresh_token: refresh_token,
          grant_type: 'refresh_token'
        })
      }).then(response => {
        const access_token = response.data.token_type + ' ' + response.data.access_token

        const refresh_token = response.data.refresh_token

        const expires = response.data.expires_in + (now.getTime() / 1000 | 0)

        const scope = response.data.scope

        this.setToken(strategy.name, access_token)
        this.setRefreshToken(strategy.name, refresh_token)
        this.setTokenExpiration(strategy.name, expires)
        this.setTokenScope(strategy.name, scope)

        this.strategy._setToken(access_token)
        return this.completeRequest(endpoint, defaults)
      }).catch(() => {
        return this.completeRequest(endpoint, defaults)
      })
    } else {
      return this.completeRequest(endpoint, defaults)
    }
  }

  requestWith (strategy, endpoint, defaults) {
    const token = this.getToken(strategy)

    const _endpoint = Object.assign({}, defaults, endpoint)

    if (!_endpoint.headers) {
      _endpoint.headers = {}
    }
    if (!_endpoint.headers['Authorization'] && isSet(token) && token) {
      _endpoint.headers['Authorization'] = token
    }

    return this.request(_endpoint)
  }

  wrapLogin (promise) {
    this.$storage.setState('busy', true)
    this.error = null

    return Promise.resolve(promise)
      .then(() => {
        this.$storage.setState('busy', false)
      })
      .catch(error => {
        this.$storage.setState('busy', false)
        return Promise.reject(error)
      })
  }

  onError (listener) {
    this._errorListeners.push(listener)
  }

  callOnError (error, payload = {}) {
    this.error = error

    for (let fn of this._errorListeners) {
      fn(error, payload)
    }
  }

  redirect (name, noRouter = false) {
    if (!this.options.redirect) {
      return
    }

    const from = this.options.fullPathRedirect ? this.ctx.route.fullPath : this.ctx.route.path

    let to = this.options.redirect[name]
    if (!to) {
      return
    }

    // Apply rewrites
    if (this.options.rewriteRedirects) {
      if (name === 'login' && isRelativeURL(from) && !isSameURL(to, from)) {
        this.$storage.setUniversal('redirect', from)
      }

      if (name === 'home') {
        let redirect = this.$storage.getUniversal('redirect')
        const cookie = this.ctx.app.$cookies.get('oauth-redirect')
        if (cookie && !redirect) {
          redirect = cookie
          this.ctx.app.$cookies.remove('oauth-redirect')
        }
        this.$storage.setUniversal('redirect', null)

        if (isRelativeURL(redirect)) {
          to = redirect
        }
      }
    }

    // Prevent infinity redirects
    if (isSameURL(to, from)) {
      return
    }

    if (process.browser) {
      if (noRouter) {
        window.location.replace(to)
      } else {
        this.ctx.redirect(to)
      }
    } else {
      this.ctx.redirect(to)
    }
  }

  hasScope (scope) {
    const userScopes = this.getTokenScope(this.strategy.name)

    if (!userScopes) {
      return undefined
    }

    if (Array.isArray(userScopes)) {
      return userScopes.includes(scope)
    }

    return Boolean(getProp(userScopes, scope))
  }
}
