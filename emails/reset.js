const keys = require('../keys')

module.exports = function(email, token) {
  return {
    to: email,
    from: keys.EMAIL_FROM,
    subject: 'Reset your password',
    html: `
      <h1>You want to reset your password?</h1>
      <p>Click link below</p>
      <a href="${keys.BASE_URL}/auth/password/${token}">Reset password</a>
      <hr />
      <a href="${keys.BASE_URL}">Our site</a>
    `
  }
}