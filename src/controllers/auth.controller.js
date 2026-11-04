const userModel = require("../models/user.model.js");
const jwt = require("jsonwebtoken");

// user register controller
async function register(req, res) {
  try {
    const { username, email, password } = req.body;
    const isExistingUser = await userModel.findOne({ email });

    if (isExistingUser) {
      return res.status(422).json({ message: "User already exists" });
    }

    const user = await userModel.create({ username, email, password });
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "3d" },

      res.cookies("token", token, {
        httpOnly: true,

        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 3 * 24 * 60 * 60 * 1000, // 3 days
      }),
    );

    return res.status(201).json({
      message: "User registered successfully",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
      token,
    });
  } catch (error) {
    return res.status(500).json({
      message: "Something went wrong",
      error: error.message,
    });
  }
}

module.exports = {
  register,
};
