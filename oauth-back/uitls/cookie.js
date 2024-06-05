exports.sendTokenResponse = (statusCode, res, token, data) => {
  //Create token
  //   const options = {
  //     expires: new Date(
  //       Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000
  //     ),
  //     httpOnly: true,
  //   };

  res.status(statusCode).cookie("token", token).json({
    success: true,
    token,
    data,
  });
};
