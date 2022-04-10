const localStrategyMongoose = require('passport-local-mongoose');


const mongoose = require('mongoose');


let User = new mongoose.Schema({
    username: String,
    email: String,
    password: {type: String, select: false},
    resetPasswordToken: String,
    resetPasswordExpires: Date
});

User.plugin(localStrategyMongoose, {usernameField : 'email'});
const Users = mongoose.model('Users', User);

module.exports = Users;