import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.models.js";
// import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";


const generateAccessAndRefreshToken = async (userid) => {
    try {
        const user = await User.findById(userid);

        const accessToken = await user.generateAccessToken();
        const refreshToken = await user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ValidateBeforeSave: false});  // Save Refresh Token in DB

        return {accessToken, refreshToken}; 

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating Access and Refresh Token")
    }
}


const registerUser = asyncHandler( async (req, res) => {
    // Get User details from the frontend
    // Validation -> Not empty
    // Check if user already exist or not  ((Check username) (check email))
    // Check for images , Check for avatar
    // Upload them to Cloudinary

    // Create user object -> Create entry in DB
    // Remove password and refresh token field   From the Response
    // Check for user creation
    // Return Response



    // Get user details
    const { username, email, password, fullName } = req.body;
    


    // Validation process
    if(fullName == ""){
        throw new ApiError(400, "FullName is required")
    }
    else if(username == ""){
        throw new ApiError(400, "Username is required")
    }
    else if(email == ""){
        throw new ApiError(400, "Email is required")
    }
    else if(password == ""){
        throw new ApiError(400, "Password is required")
    }



    // Check if User is already exist or not (If exist then throw error .....That user is already exist)
    const UserExist = await User.findOne({
        $or: [{username}, {email}]
    })

    if(UserExist){
        throw new ApiError(409, "User already exist")
    }


    // console.log(req.files)


    // Create User
    const user = await User.create({
        username: username.toLowerCase(),
        email, 
        password,
        fullName
    })


    // Remove password and refresh token field   From the Response
    const createdUser = await User.findById(user._id).select("-password -refreshToken")

    if(!createdUser){
        throw new ApiError(500, "Something went wrong While registring user")
    }


    // Return Response
    return res.status(201).json(
        new ApiResponse(201, createdUser, "User registred Successfully")
    )
}) 

const loginUser = asyncHandler( async (req, res) => {
    // Get User details from the frontend
    // Check Username or email
    // Check if user exist or not
    // If Password Check is correct ==> THen Access and Refresh Token
    // Refresh Token is send through Cookie
    // Check for user creation
    // Return Response
    


    // Get User details from (req.body)
    const {username, email, password} = req.body;


    // Validation
    if(!(username || email)){
        throw new ApiError(400, "Username or Email is required")
    }

    // Check if User is already exist or not
    const user = await User.findOne({
        $or: [{username}, {email}]
    })


    if(!user){
        throw new ApiError(404, "User not found")
    }


    // Check password
    const isPasswordValid = await user.isPasswordCorrect(password)


    if(!isPasswordValid){
        throw new ApiError(401, "Password is incorrect")
    }


    // Generate Access and Refresh Token
    const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    if(!loggedInUser){
        throw new ApiError(500, "Something went wrong while logging in user")
    }


    // Send Cookie
    const options = {
        httpOnly: true,
        secure : true,
    }

    // Send Response
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "user logged in Successfully"
        )
    )
})


const logoutUser = asyncHandler( async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, 
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    // Remove Cookie
    const options = {
        httpOnly: true,
        secure : true,
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(
        new ApiResponse(200, {}, "User logged out Successfully")
    )   
})


const refreshAccessToken = asyncHandler( async (req, res) => {
    // First Take the refresh token from the cookie
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;


    if(!incomingRefreshToken){
        throw new ApiError(401, "Unauthorized Request")
    }

    try {
        const decodedRefreshToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET) 
    
        const user = await User.findById(decodedRefreshToken?._id).select("-password -refreshToken")
    
    
        if(!user){
            throw new ApiError(401, "Invalid Refresh Token")
        }
    
    
        // Check refresh token (in database and in User)
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "Refresh Token is Expired or used")
        }
            
    
        // Now generate new Refresh Token and Access token 
        const {accessToken, newRefreshToken} = await generateAccessAndRefreshToken(user._id)
    
    
        // Send Cookie
        const options = {
            httpOnly: true,
            secure : true,
        }
    
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user, accessToken, refreshToken: newRefreshToken 
                },
                "Access Token Refreshed Successfully"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid Refresh Token")
    }
})


const changeCurrentPassword = asyncHandler( async (req, res) => {
    const {oldPassword, newPassword} = req.body


    // First I need to take user from req.user
    const user = await User.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(400, "Old Password is incorrect")
    }

    // Now we need to set new password
    user.password = newPassword
    await user.save({ValidateBeforeSave: false})

    // Send Response
    return res
    .status(200)
    .json(
        new ApiResponse(
            200, 
            {},
            "Password Changed Successfully"
        )
    )
})

const getCurrentUser = asyncHandler( async (req, res) => {
    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            {
                user: req.user
            },
            "User Fetched Successfully"
        )
    )
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser
}