import dotenv from "dotenv";
import connectDB from "./db/index.js";
import {app} from "./app.js";
dotenv.config({path: "./.env"});

connectDB()
.then(() => {
        const PORT = process.env.PORT || 8000;
        console.log("🔌 DB connected successfully");

        app.listen(PORT, () => {
            console.log(`✅ Server is running at http://127.0.0.1:${PORT}`);
        });
    })
.catch((error) => console.error('Error connecting to MongoDB:', error));



