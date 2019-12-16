const {Router} = require('express')
const Course = require('../models/course')
const auth = require('../middleware/auth')
const router = Router()

router.get('/', async (req, res) => {
  const courses = await Course.find()
    .populate('userId', 'email name')
    
  res.render('courses', {
    pageTitle: 'Courses page', 
    isCourses: true, 
    courses
  })
})

router.get('/:id/edit', auth, async (req, res) => {
  if (!req.query.allow) {
    return res.redirect('/')
  } else {
    const course = await Course.findById(req.params.id)
    res.render('course-edit', {course})
  }
})

router.post('/edit', auth, async (req, res) => {
  const {id} = req.body
  delete req.body.id
    await Course.findByIdAndUpdate(id, req.body)
    res.redirect('/courses')
})

router.post('/remove', auth, async (req, res) => {
  try{
    await Course.deleteOne({ _id: req.body.id})
    res.redirect('/courses')
  } catch(err) {
    console.log(err)
  }
})

router.get('/:id', async (req, res) => {
  const course = await Course.findById(req.params.id)
  res.render('course', {layout: 'empty', pageTitle: `Course ${course.name}`, course})
})

module.exports = router