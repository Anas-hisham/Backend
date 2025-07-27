require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { body, validationResult } = require('express-validator');
const validator = require('validator');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Constants
const httpStatusText = {
    SUCCESS: "success",
    FAIL: "fail",
    ERROR: "error"
};

const userRoles = {
    ADMIN: "ADMIN",
    USER: "USER",
    MANGER: "MANGER"
};

// AppError Class
class AppError extends Error {
    create(message, statusCode = 500, statusText = httpStatusText.ERROR) {
        this.message = message;
        this.statusCode = statusCode;
        this.statusText = statusText;
        return this;
    }
}
const appError = new AppError();

// Connect MongoDB
mongoose.connect(process.env.MONGO_URL).then(() => console.log("MongoDB connected"));

// Models
const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: {
        type: String, required: true, unique: true,
        validate: [validator.isEmail, 'field must be a valid email address']
    },
    password: { type: String, required: true },
    token: { type: String },
    role: {
        type: String, enum: [userRoles.USER, userRoles.ADMIN, userRoles.MANGER],
        default: userRoles.USER
    },
    avatar: { type: String, default: 'uploads/profile.png' }
});
const User = mongoose.model('User', userSchema);

const courseSchema = new mongoose.Schema({
    title: { type: String, required: true },
    price: { type: Number, required: true }
});
const Course = mongoose.model('Course', courseSchema);

// Middleware
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return next(appError.create('token is required', 401));

    const token = authHeader.split(' ')[1];
    try {
        const currentUser = jwt.verify(token, process.env.JWT_SECRET_KEY);
        req.currentUser = currentUser;
        next();
    } catch {
        return next(appError.create('invalid token', 401));
    }
};

const allowedTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.currentUser.role)) {
            return next(appError.create('this role is not authorized', 401));
        }
        next();
    };
};

// JWT Helper
const generateJWT = async (payload) => {
    return await jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });
};

// Validation
const courseValidation = () => [
    body('title')
        .notEmpty().withMessage("title is required")
        .isLength({ min: 2 }).withMessage("title must be at least 2 characters"),
    body('price')
        .notEmpty().withMessage("price is required")
];

// Routes
app.get('/api/courses', async (req, res, next) => {
    try {
        const limit = +req.query.limit || 10;
        const page = +req.query.page || 1;
        const skip = (page - 1) * limit;

        const courses = await Course.find({}, { "__v": false }).limit(limit).skip(skip);
        res.json({ status: httpStatusText.SUCCESS, data: { courses } });
    } catch (err) {
        next(err);
    }
});

app.get('/api/courses/:courseId', async (req, res, next) => {
    try {
        const course = await Course.findById(req.params.courseId);
        if (!course) return next(appError.create('course not found', 404, httpStatusText.FAIL));
        res.json({ status: httpStatusText.SUCCESS, data: { course } });
    } catch (err) {
        next(err);
    }
});

app.post('/api/courses', verifyToken, allowedTo(userRoles.MANGER), courseValidation(), async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return next(appError.create(errors.array(), 400, httpStatusText.FAIL));

        const newCourse = new Course(req.body);
        await newCourse.save();
        res.status(201).json({ status: httpStatusText.SUCCESS, data: { course: newCourse } });
    } catch (err) {
        next(err);
    }
});

app.patch('/api/courses/:courseId', async (req, res, next) => {
    try {
        const updated = await Course.updateOne({ _id: req.params.courseId }, { $set: req.body });
        res.json({ status: httpStatusText.SUCCESS, data: { course: updated } });
    } catch (err) {
        next(err);
    }
});

app.delete('/api/courses/:courseId', verifyToken, allowedTo(userRoles.ADMIN, userRoles.MANGER), async (req, res, next) => {
    try {
        await Course.deleteOne({ _id: req.params.courseId });
        res.json({ status: httpStatusText.SUCCESS, data: null });
    } catch (err) {
        next(err);
    }
});

// User Routes
app.get('/api/users', verifyToken, async (req, res, next) => {
    try {
        const limit = +req.query.limit || 10;
        const page = +req.query.page || 1;
        const skip = (page - 1) * limit;

        const users = await User.find({}, { password: false, __v: false }).limit(limit).skip(skip);
        res.json({ status: httpStatusText.SUCCESS, data: { users } });
    } catch (err) {
        next(err);
    }
});

app.post('/api/users/register', async (req, res, next) => {
    try {
        const { firstName, lastName, email, password, role } = req.body;

        if (await User.findOne({ email })) return next(appError.create('user already exists', 400, httpStatusText.FAIL));

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ firstName, lastName, email, password: hashedPassword, role });
        newUser.token = await generateJWT({ email: newUser.email, id: newUser._id, role: newUser.role });

        await newUser.save();
        res.status(201).json({ status: httpStatusText.SUCCESS, data: { user: newUser } });
    } catch (err) {
        next(err);
    }
});

app.post('/api/users/login', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return next(appError.create('email and password are required', 400, httpStatusText.FAIL));

        const user = await User.findOne({ email });
        if (!user) return next(appError.create('user not found', 400, httpStatusText.FAIL));

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return next(appError.create('invalid credentials', 401, httpStatusText.FAIL));

        const token = await generateJWT({ email: user.email, id: user._id, role: user.role });
        res.json({ status: httpStatusText.SUCCESS, data: { token } });
    } catch (err) {
        next(err);
    }
});

// Not Found
app.all('*', (req, res) => {
    res.status(404).json({ status: httpStatusText.ERROR, message: 'This resource is not available' });
});

// Global Error Handler
app.use((error, req, res, next) => {
    res.status(error.statusCode || 500).json({
        status: error.statusText || httpStatusText.ERROR,
        message: error.message,
        code: error.statusCode || 500,
        data: null
    });
});

app.listen(process.env.PORT || 4000, () => console.log("Server listening on port 4000"));
