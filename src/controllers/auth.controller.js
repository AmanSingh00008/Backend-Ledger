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

      res.cookie("token", token, {
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

async function login(req, res) {
  const { email, password } = req.body;

  const user = await userModel.findOne({ email }).select("+password")

  if (!user) {
    return res.status(401).json({ message: "Email or password is INVALID" });
  }

  const isValidPassword = user.comparePassword(password);
  if (!isValidPassword) {
    return res.status(401).json({ message: "Email or Password is INVALID" });
  }

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });

  res.cookie("token", token);

  res.status(200).json({
    _id: user._id,
    email: user.email,
    name: user.name,
  });

}

async function logout(req, res) {
  res.clearCookie("token");
  res.status(200).json({ message: "Logged out successfully" });
}

module.exports = {
  register,
  login,
  logout,
};
