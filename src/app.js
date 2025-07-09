import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

// Middlewares  ==>> We "use" these middlewares
app.use(cors({
    origin: process.env.CORS_ORIGIN,
    Credentials: true
}))

app.use(express.json()); // for JSON payloads
app.use(express.urlencoded({ extended: true })); // for form data
app.use(express.static("public"));

app.use(cookieParser());


// Routes
import userRouter from "./routes/user.routes.js";

//Routes declaration
app.use("/api/v1/users", userRouter)

// https://localhost:8000/api/v1/users/register



export { app }