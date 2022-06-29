const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please tell us your name'],
  },

  email: {
    type: String,
    required: [true, 'Please provide your email'],
    lowercase: true,
    unique: true,
    validate: [validator.isEmail, 'Please provide a valid email'],
  },

  photo: {
    type: String,
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false, //doesn't show the password in the database
  },
  role: {
    type: String,
    enum: ['user', 'guide', 'lead-guide', 'admin'],
    default: 'user',
  },
  passwordConfirm: {
    type: String,
    required: [true, 'please Confirm your password'],
    validate: {
      //This only works on CREATE and on save
      validator: function (el) {
        return el === this.password;
      },
      message: 'passwords are not the same',
    },
  },
  passwordChangedAt: {
    type: Date,
  },
  passwordResetToken: String,
  passwordResetExpires: Date,
  active:{
    type: Boolean,
    default:true,
    select: false
  }
});


//These middlewares run before a file is saved to the database
userSchema.pre('save', async function (next) {
  //Only run the function if password was modified
  if (!this.isModified('password')) return next();

  //Hash the password with cost of 12 in the database
  this.password = await bcrypt.hash(this.password, 12);
  //Delete the passwordConfirm field`
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre("save", function(next){
  //if we didn't modify the password or we created a new document it means that we should go to the next middleware 
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangeAt = Date.now() -1000

  next()
}) 

//Query middleware points to the current query
userSchema.pre(/^find/, function(next){
  //This points to the current query
  this.find({active: {$ne: false}})

  next()
})

//Check if password match
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    console.log(changedTimestamp, JWTTimestamp);
    return JWTTimestamp < changedTimestamp;
  }

  //false means NOT changed
  return false;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');

  //Encrypting the passwordResetToken in the database for security reasons
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

    console.log({resetToken}, this.passwordResetToken)
  //Setting the passwordResetExpires to 10 minutes
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  //return the unencrypted token to the user via email
  return resetToken
};

const User = mongoose.model('User', userSchema);

module.exports = User;
