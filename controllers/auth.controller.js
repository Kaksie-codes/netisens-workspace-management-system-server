import handleError from "../utils/error.js";
import User from "../models/user.model.js";
import bcrypt from 'bcrypt';


let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

// @desc Register a new User
// @route POST: /api/auth/signup
// @access Public
const signupUser = async (req, res, next) => {
    const { username, email, password, phone_number, gender } = req.body;

    try{ 
        // validating the data from the frontend
        if(username.length < 3){
            return next(handleError(403, "Username must be at least three letters long" ));        
        }
        if(!email.length){
            return next(handleError(403, "Enter email" ));
        }
        if(!emailRegex.test(email)){
            return next(handleError(403, "Email is Invalid" ));       
        }
        if(!passwordRegex.test(password)){
            return next(handleError(403, "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters." ));         
        }

        //check if the user already exists in the database
        const emailExists = await User.findOne({"personal_info.email":email});
        const usernameExists = await User.findOne({"personal_info.username": username});


        if(usernameExists){
            return next(handleError(403, "Username is already in use" ));         
        }
        if(emailExists){
            return next(handleError(403, "Email is already in use"));         
        }       

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
    
        // Create a new User
        const newUser = new User({
            personal_info:{            
                username,
                email,
                phone_number, 
                gender,                
                password: hashedPassword            
            }        
        });

        // save the user
        await newUser.save();
        
        // send verification link to the user
        // await sendVerificationEmail(newUser);   

        return res.status(200).json({
            success: true,
            status: 'verification pending', 
            statusCode:200,
            message: `verification link sent to your email'`,                     
        })         
    }catch(error){
        if(error.code === 11000){
            return next(handleError(500, "Username already Exists"));
        }
        return next(error);
    }    
}

const signinUser = async(req, res, next) => {

}

const resetOtp = async(req, res, next) => {

}
export { signupUser, signinUser, resetOtp }