const {Router} = require('express')
const router = Router()
const bcrypt = require('bcryptjs')
const User = require('../models/user')

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
    }
  } catch(err) {
    console.log(err)
  }
})



module.exports = router