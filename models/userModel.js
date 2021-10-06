const crypto = require('crypto')
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

//name email photo password passwordConfirm

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please tell us your name!']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  photo: String,
  role:{
    type: String,
    enum:['user','guide','lead-guide','admin'],
    default: 'user'
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      validator: function(el) {
        return el === this.password;
      },
      message: 'Passwords are not the same !'
    }
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date
});

userSchema.pre('save', async function(next) {
  //only run this function if password was modified
  if (!this.isModified('password')) return next();
  //hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);
  //delete passwordConfim field
  this.passwordConfirm = undefined;
  next();
});

//middleware that runs before the new document actually saved les 136
userSchema.pre('save',function(next){
    if (!this.isModified('password') || this.isNew) return next();

    this.passwordChangedAt = Date.now()-1000; // make it 1 second in the past in order to ensure token is created after password has been changed

    next();
})

userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function(JWTTimestamp){
    if (this.passwordChangedAt){

        const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10)
        // console.log('passwordChangedAt',this.passwordChangedAt)
        // console.log('JWTTimestamp',JWTTimestamp)

        return JWTTimestamp < changedTimestamp // returns boolean for true like 300 < 200 
    }
    //false means not changed
    return false;
}

userSchema.methods.createPasswordResetToken = function(){
    const resetToken = crypto.randomBytes(32).toString('hex');

    //saved within schema but has to be encrypted for safety
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    console.log({resetToken},this.passwordResetToken)

    this.passwordResetExpires = Date.now() + 10 * 60*1000;
    return resetToken
}

const User = mongoose.model('User', userSchema);

module.exports = User;
