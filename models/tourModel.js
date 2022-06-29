const mongoose = require('mongoose');
const slugify = require('slugify');
//const User = require("./userModel")
//const validator = require('validator');

const tourSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'A tour must have a name'],
      unique: true,
      trim: true, //Trim is used to remove the whitespaces at the end and beginning of a statement
      maxlength: [40, 'A tour name must not be greater than 40 characters'],
      minlength: [10, 'A tour name must not be greater than 40 characters'],
      // validate: [validator.isAlpha, "Tour name must only contain characters"]
    },
    slug: {
      type: String,
    },
    duration: {
      type: Number,
      required: [true, 'A tour must have a duration'],
    },
    maxGroupSize: {
      type: Number,
      required: [true, 'A tour must have a group size'],
    },
    difficulty: {
      type: String,
      required: [true, 'A tour must have a string'],
      enum: {
        values: ['easy', 'medium', 'difficult'],
        message: 'difficulty is either easy, medium, difficult',
      },
    },
    ratingsAverage: {
      type: Number,
      default: 4.5,
      min: [1, 'Rating must be above 1.0'],
      max: [5, 'Rating must be below 5.0'],
    },
    ratingsQuantity: {
      type: Number,
      default: 0,
    },
    price: {
      type: Number,
      required: [true, 'A tour must have a price'],
    },
    priceDiscount: {
      type: Number,
      validate: {
        validator: function (val) {
          //this keyword only points to current doc on new document creation
          return val < this.price;
        },
        message: 'Discount price ({VALUE})should be below regular price',
      },
    },
    summary: {
      type: String,
      trim: true,
      required: [true, 'Tour must have a summary'],
    },
    description: {
      type: String,
      trim: true,
    },
    imageCover: {
      type: String,
      required: [true, 'A tour must have a cover image'],
    },
    images: [String],
    createdAt: {
      type: Date,
      default: Date.now(),
      select: false,
    },
    startDates: [Date],
    secretTour: {
      type: Boolean,
      default: false,
    },
    startLocation: {
      //GeoJSON
      type: {
        type: String,
        default: 'Point',
        enum: ['Point'],
      },
      coordinates: [Number],
      address: String,
      description: String,
    },
    locations: [
      {
        type: {
          type: String,
          default: 'Point',
          enum: ['Point'],
        },
        coordinates: [Number],
        address: String,
        description: String,
        day: Number
      },
    ],
    guides: [
      {
        type: mongoose.Schema.ObjectId,
        ref: "User"
      }
    ]
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

tourSchema.virtual('durationWeeks').get(function () {
  return this.duration / 7;
});
//Note an arrow function does not get its own this keyword

//DOCUMENT MIDDLEWARE: runs before .save() and .create()
tourSchema.pre('save', function (next) {
  console.log(this); //returns the document
  this.slug = slugify(this.name, { lower: true });
  next();
});

//Embedding the users document in the tour guides() 
// tourSchema.pre('save', async function (next){
//   const guidesPromises = this.guides.map(async(id) => await User.findById(id))
//   this.guides = await Promise.all(guidesPromises)
//   next()
// });

// tourSchema.pre("save", function(next){
//   console.log("Will save new document.....")
//   next()
// })
// tourSchema.post("save", function(doc, next){
//   console.log(doc);
//   next()
// })

//QUERY MIDDLEWARE
tourSchema.pre(/^find/, function (next) {
  this.find({ secretTour: { $ne: true } }); //We are looking for tours that don't have secretTour set to true
  this.start = Date.now();
  next();
});

tourSchema.pre(/^find/, function(next){
  this.populate({
    path: "guides",
    select: "-__v -passwordChangedAt"
  })

  next()
})
// /^find/ is used so that the middleware will be executed for all the commands that start with find e.g find one, find one and update, find one and delete

tourSchema.post(/^find/, function (docs, next) {
  console.log(`query took ${Date.now() - this.start} milliseconds`);
  //console.log(docs)
  next();
});

//AGGREGATION MIDDLEWARE
tourSchema.pre('aggregate', function (next) {
  this.pipeline().unshift({ $match: { secretTour: { $ne: true } } });

  next();
});
const Tour = mongoose.model('Tour', tourSchema);

// const testTour = new Tour({
//   name: 'The Park Camper',
//   price: 997,
// });

// testTour
//   .save()
//   .then((doc) => {
//     console.log(doc);
//   })
//   .catch((err) => {
//     console.log(err);
//   });

module.exports = Tour;
