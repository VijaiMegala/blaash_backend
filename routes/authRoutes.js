const express = require('express');
const { signUp, login, verifyOtp } = require('../controllers/authController');

const router = express.Router();

router.post('/signup', signUp);
router.post('/login', login);
router.post('/verify-otp', verifyOtp);

module.exports = router;
