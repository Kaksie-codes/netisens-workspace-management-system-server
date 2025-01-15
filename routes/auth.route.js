import { Router } from "express";
import { signupUser } from "../controllers/auth.controller.js";


// Initialize the router
const router = Router();

// Signup
router.post('/signup', signupUser);


export default router;