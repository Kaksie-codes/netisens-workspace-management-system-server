import { Router } from "express";
import { resetOtp, signinUser, signupUser } from "../controllers/auth.controller.js";


// Initialize the router
const router = Router();

// Signup
router.post('/signup', signupUser);

// signin
router.post('signin', signinUser);

// Reset OTP
router.post('/resetOtp', resetOtp)


export default router;