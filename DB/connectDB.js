const mongoose = require('mongoose');
mongoose.set('strictQuery', false);

const connectDB = async (uri)=>{

    try {
        await mongoose.connect(uri);
        console.log('Connected With DB');
    } catch (error) {
        console.log(error);
        throw error;
    }
}

module.exports = connectDB;
