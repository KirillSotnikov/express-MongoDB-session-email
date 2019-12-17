const {Router} = require('express')
const router = Router()
const crypto = require('crypto')
const nodemailer = require('nodemailer')
const sendGrid = require('nodemailer-sendgrid-transport')
const bcrypt = require('bcryptjs')
const User = require('../models/user')
const keys = require('../keys')

const regEmail = require('../emails/registration')
const resetEmail = require('../emails/reset')

const transporter = nodemailer.createTransport(sendGrid({
  auth: {
    api_key: keys.SENDGRID_API_KEY
  }
}))

router.get('/login', async (req, res) => {
  res.render('auth/login', {
    pageTitle: 'Login',
    isLogin: true,
    registerError: req.flash('registerError'),
    loginError: req.flash('loginError')
  })
})

router.post('/login', async (req, res) => {
  try{
    const {email, password} = req.body

    const candidate = await User.findOne({email})

    if(candidate) {
      const isSame = await bcrypt.compare(password, candidate.password)

      if(isSame) {
        req.session.user = candidate
        req.session.isAuthenticated = true
        req.session.save(err => {
          if(err) throw err
      
          res.redirect('/')
        })
      } else {
        req.flash('loginError', 'Password is incorrect.')
        res.redirect('/auth/login#login')
      }
    } else {
      req.flash('loginError', 'User is not found!')
      res.redirect('/auth/login#login')
    }
  } catch (err) {
    console.log(err)
  }
})

router.get('/logout', async (req, res) => {
  req.session.destroy(() => {
    res.redirect('/auth/login#login')
  })
})

router.post('/registration', async (req, res) => {
  try{
    const {email, password, repeat, name} = req.body

    const candidate = await User.findOne({ email })

    if(candidate) {
      req.flash('registerError', 'User with this email is already exists')
      res.redirect('/auth/login#registration')
    } else {
      const hashPassword = await bcrypt.hash(password, 10)
      const user = new User({
        email,
        name,
        password: hashPassword,
        cart: { items: [] }
      })
      await user.save()
      res.redirect('/auth/login#login')
      await transporter.sendMail(regEmail(email))
    }
  } catch(err) {
    console.log(err)
  }
})

router.get('/reset', async (req, res) => {
  res.render('auth/reset', {
    pageTitle: 'Reset password',
    error: req.flash('error')
  })
})

router.post('/reset', (req, res) => {
  try{
    crypto.randomBytes(32, async (err, buffer) => {
      if(err){
        req.flash('error', 'Something went wrong... Try again later')
        return res.redirect('/auth/reset')
      }

      const token = buffer.toString('hex')
      
      const candidate = await User.findOne({email: req.body.email})

      if(candidate) {
        candidate.resetToken = token
        candidate.resetTokenExp = Date.now() + 60 * 60 * 1000 // 1 hour
        await candidate.save()

        await transporter.sendMail(resetEmail(candidate.email, token))
        res.redirect('/auth/login')
      } else {
        req.flash('error', 'Wrong email')
        res.redirect('/auth/reset')
      }
    })
  } catch (err){
    console.log(err)
  }
})

module.exports = router