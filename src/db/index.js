import mongoose from "mongoose";
console.log(process.env.MONGO_URL);

const connectDB = async () => {
    try {
        const connectionInstance = await mongoose.connect(process.env.MONGO_URL);
        console.log(`MongoDB Connected: ${connectionInstance.connection.host}`);
    } catch (error) {
        console.error("Error Msg: ", error);
        process.exit(1);
    }
}

export default connectDB;